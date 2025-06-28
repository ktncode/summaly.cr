# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2025 Kotone <git@ktn.works>

require "kemal"
require "json"
require "http/client"
require "myhtml"
require "uri"
require "log"

struct ConfigFile
  include JSON::Serializable

  property bind_addr : String = "0.0.0.0:3000"
  property timeout : UInt64 = 5000_u64
  property user_agent : String = "Summaly.cr <https://github.com/ktncode/summaly.cr>"
  property max_size : UInt32 = 2_097_152_u32
  property proxy : String? = nil
  property media_proxy : String? = nil
  property append_headers : Array(String) = [
    "Content-Security-Policy:default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'",
    "Access-Control-Allow-Origin:*"
  ]

  def append_headers_to(headers : HTTP::Headers) : Nil
    @append_headers.each do |header_line|
      next unless separator_index = header_line.index(':')
      next if separator_index + 1 >= header_line.size
      
      key = header_line[0...separator_index]
      value = header_line[separator_index + 1..-1]
      headers[key] = value
    end
  end
end

struct RequestParams
  include JSON::Serializable

  property url : String
  property lang : String? = nil
  @[JSON::Field(key: "userAgent")]
  property user_agent : String? = nil
  @[JSON::Field(key: "responseTimeout")]
  property response_timeout : UInt32? = nil
  @[JSON::Field(key: "contentLengthLimit")]
  property content_length_limit : UInt32? = nil
end

# OEmbed specification implementation
struct OEmbed
  include JSON::Serializable

  property type : String
  property version : String
  property title : String? = nil
  property author_name : String? = nil
  property author_url : String? = nil
  property provider_name : String? = nil
  property provider_url : String? = nil
  property cache_age : Float64? = nil
  property thumbnail_url : String? = nil
  property thumbnail_width : Float64? = nil
  property thumbnail_height : Float64? = nil
  property url : String? = nil
  property html : String? = nil
  property width : Float64? = nil
  property height : Float64? = nil
end

# Video/media player configuration
struct SummalyPlayer
  include JSON::Serializable

  property url : String? = nil
  property width : Float64? = nil
  property height : Float64? = nil
  property allow : Array(String) = [] of String
end

# Primary API response structure
struct SummalyResult
  include JSON::Serializable

  property url : String
  property title : String? = nil
  property icon : String? = nil
  property description : String? = nil
  property thumbnail : String? = nil
  property sitename : String? = nil
  property player : JSON::Any = JSON::Any.new({} of String => JSON::Any)
  property sensitive : Bool = false
  @[JSON::Field(key: "activityPub")]
  property activity_pub : String? = nil
  property oembed : OEmbed? = nil
end

class RateLimit
  @hosts = {} of String => UInt32
  @mutex = Mutex.new

  def request_allowed?(url : String) : Bool
    host = extract_host(url)
    return false unless host

    @mutex.synchronize do
      current_requests = @hosts[host]? || 0_u32
      if current_requests < 3
        @hosts[host] = current_requests + 1
        true
      else
        false
      end
    end
  end

  def complete_request(url : String) : Nil
    host = extract_host(url)
    return unless host

    spawn do
      sleep 500.milliseconds
      @mutex.synchronize do
        current_requests = @hosts[host]? || 0_u32
        if current_requests > 1
          @hosts[host] = current_requests - 1
        else
          @hosts.delete(host)
        end
      end
    end
  end

  private def extract_host(url : String) : String?
    URI.parse(url).host
  rescue
    nil
  end
end

# HTML entity decoding helper
def decode_html_entities(text : String) : String
  text
    .gsub("&amp;", "&")
    .gsub("&lt;", "<")
    .gsub("&gt;", ">")
    .gsub("&quot;", "\"")
    .gsub("&#39;", "'")
    .gsub("&nbsp;", " ")
end

def resolve_relative_url(url : String, base_uri : URI, base_url_str : String, media_proxy : String?, proxy_filename : String) : String?
  absolute_url = case
                 when url.starts_with?("//")
                   "#{base_uri.scheme}:#{url}"
                 when url.starts_with?("/")
                   "#{base_url_str}#{url}"
                 when !url.starts_with?("http")
                   construct_relative_url(url, base_uri, base_url_str)
                 else
                   url
                 end

  apply_media_proxy(absolute_url, media_proxy, proxy_filename)
end

private def construct_relative_url(relative_path : String, base_uri : URI, base_url_str : String) : String
  base_path = base_uri.path || "/"
  
  if base_path.ends_with?("/")
    "#{base_url_str}#{base_path}#{relative_path}"
  else
    directory = File.dirname(base_path)
    directory = "/" if directory == "."
    "#{base_url_str}#{directory}/#{relative_path}"
  end
end

private def apply_media_proxy(url : String, media_proxy : String?, proxy_filename : String) : String
  if media_proxy
    "#{media_proxy}#{proxy_filename}?url=#{URI.encode_www_form(url)}"
  else
    url
  end
end

def process_html_content(response : HTTP::Client::Response, size_limit : UInt64) : String?
  # Check content length headers
  if content_length = response.headers["Content-Length"]?
    return nil if content_length.to_u64? && content_length.to_u64 > size_limit
  end

  buffer = IO::Memory.new
  bytes_read = 0_u64
  
  # Read response in chunks to respect size limit
  while chunk = response.body_io.read(Bytes.new(8192))
    break if chunk.empty?
    
    bytes_read += chunk.size
    return nil if bytes_read > size_limit
    
    buffer.write(chunk)
  end
  
  content_bytes = buffer.to_slice
  detect_and_convert_encoding(content_bytes)
end

# Character encoding detection and conversion
private def detect_and_convert_encoding(bytes : Bytes) : String
  # First, try to read as UTF-8
  content = String.new(bytes, "UTF-8", invalid: :skip)
  
  # Look for charset declarations in HTML meta tags
  charset_patterns = [
    /<meta[^>]+charset\s*=\s*["']?([^"'>\s]+)/i,
    /<meta[^>]+http-equiv\s*=\s*["']?content-type["']?[^>]*charset\s*=\s*([^"';\s]+)/i
  ]
  
  charset_patterns.each do |pattern|
    if match = content.match(pattern)
      charset = match[1].downcase
      return handle_charset_conversion(bytes, charset)
    end
  end
  
  content
end

private def handle_charset_conversion(bytes : Bytes, charset : String) : String
  case charset
  when "utf-8", "utf8"
    String.new(bytes, "UTF-8", invalid: :skip)
  when "shift_jis", "shift-jis", "sjis", "euc-jp", "iso-2022-jp"
    # For now, fallback to UTF-8 conversion with invalid char skipping
    # A full implementation would use iconv or similar for proper conversion
    String.new(bytes, "UTF-8", invalid: :skip)
  else
    String.new(bytes, "UTF-8", invalid: :skip)
  end
end

# Metadata extraction from HTML document
def extract_metadata(html_content : String, base_uri : URI, config : ConfigFile, http_client : HTTP::Client, request_params : RequestParams) : SummalyResult
  base_url_str = "#{base_uri.scheme}://#{base_uri.host}#{base_uri.port ? ":#{base_uri.port}" : ""}"
  
  result = SummalyResult.new(url: request_params.url)
  player_data = SummalyPlayer.new

  begin
    document = parse_html_document(html_content)
    
    extract_title(document, result)
    process_meta_tags(document, result, player_data)
    process_link_tags(document, result, base_uri, base_url_str, config, http_client)
    
    finalize_result(result, player_data, base_uri, base_url_str, config)
    
  rescue ex
    Log.warn { "HTML metadata extraction failed: #{ex.message}" }
  end
  
  result
end

private def parse_html_document(html : String)
  parser = Myhtml::Parser.new
  document = parser.parse(html)
  at_exit { parser.free }
  document
end

private def extract_title(document, result : SummalyResult)
  if title_element = document.css("title").first?
    title_text = title_element.inner_text.strip
    result.title = title_text unless title_text.empty?
  end
end

private def process_meta_tags(document, result : SummalyResult, player_data : SummalyPlayer)
  document.css("meta").each do |meta_tag|
    process_meta_name_attributes(meta_tag, result)
    process_opengraph_properties(meta_tag, result, player_data)
  end
end

private def process_meta_name_attributes(meta_tag, result : SummalyResult)
  name = meta_tag.attribute_by("name")
  content = meta_tag.attribute_by("content").try { |c| decode_html_entities(c.strip) }
  
  return unless name && content
  
  case name
  when "msapplication-tooltip"
    result.description ||= content
  when "application-name"
    result.sitename ||= content
    result.title ||= content
  when "description"
    result.description ||= content
  end
end

private def process_opengraph_properties(meta_tag, result : SummalyResult, player_data : SummalyPlayer)
  property = meta_tag.attribute_by("property")
  content = meta_tag.attribute_by("content").try { |c| decode_html_entities(c.strip) }
  
  return unless property && content
  
  case property
  when "og:title"        then result.title = content
  when "og:description"  then result.description = content
  when "og:image"        then result.thumbnail = content
  when "og:url"          then result.url = content
  when "og:site_name"    then result.sitename = content
  when "og:video:url"    then player_data.url ||= content
  when "og:video:secure_url" then player_data.url = content
  when "og:video:width"  then player_data.width = content.to_f64?
  when "og:video:height" then player_data.height = content.to_f64?
  end
end

private def process_link_tags(document, result : SummalyResult, base_uri : URI, base_url_str : String, config : ConfigFile, client : HTTP::Client)
  document.css("link").each do |link_tag|
    rel = link_tag.attribute_by("rel")
    href = link_tag.attribute_by("href").try { |h| decode_html_entities(h.strip) }
    link_type = link_tag.attribute_by("type")
    
    next unless rel && href
    
    process_icon_links(rel, href, result)
    process_oembed_links(rel, link_type, href, result, base_uri, base_url_str, config, client)
  end
end

private def process_icon_links(rel : String, href : String, result : SummalyResult)
  case rel
  when "shortcut icon"  then result.icon ||= href
  when "icon"           then result.icon = href
  when "apple-touch-icon" then result.thumbnail ||= href
  end
end

private def process_oembed_links(rel : String, link_type : String?, href : String, result : SummalyResult, base_uri : URI, base_url_str : String, config : ConfigFile, client : HTTP::Client)
  return unless rel == "alternate" && link_type == "application/json+oembed"
  
  oembed_url = resolve_relative_url(href, base_uri, base_url_str, nil, "")
  return unless oembed_url
  
  fetch_oembed_data(oembed_url, result, config, client)
end

private def fetch_oembed_data(oembed_url : String, result : SummalyResult, config : ConfigFile, client : HTTP::Client)
  oembed_response = client.get(oembed_url)
  return unless oembed_response.status_code == 200
  
  content = process_html_content(oembed_response, config.max_size.to_u64)
  return unless content
  
  oembed_data = OEmbed.from_json(content)
  result.oembed = oembed_data
  
  # Extract security-conscious iframe attributes
  extract_safe_iframe_attributes(oembed_data, result)
rescue
  # Silently ignore OEmbed fetch failures
end

private def extract_safe_iframe_attributes(oembed_data : OEmbed, result : SummalyResult)
  return unless html_content = oembed_data.html
  
  safe_attributes = ["autoplay", "clipboard-write", "fullscreen", "encrypted-media", "picture-in-picture", "web-share"]
  
  if match = html_content.match(/allow=["']([^"']+)["']/)
    allowed_features = match[1].split(";").map(&.strip)
    filtered_features = allowed_features.select { |feature| safe_attributes.includes?(feature) }
    
    # Update player data if there are safe features
    if !filtered_features.empty? && result.player.as_h.empty?
      player_json = {
        "allow" => JSON::Any.new(filtered_features.map { |f| JSON::Any.new(f) })
      }
      result.player = JSON::Any.new(player_json)
    end
  end
end

private def finalize_result(result : SummalyResult, player_data : SummalyPlayer, base_uri : URI, base_url_str : String, config : ConfigFile)
  # Set player data if URL exists
  if player_data.url
    result.player = JSON.parse(player_data.to_json)
  end
  
  # Set default icon
  result.icon ||= "#{base_url_str}/favicon.ico"
  
  # Resolve all relative URLs
  resolve_result_urls(result, base_uri, base_url_str, config)
end

private def resolve_result_urls(result : SummalyResult, base_uri : URI, base_url_str : String, config : ConfigFile)
  if icon = result.icon
    result.icon = resolve_relative_url(icon, base_uri, base_url_str, config.media_proxy, "icon.webp")
  end
  
  if thumbnail = result.thumbnail
    result.thumbnail = resolve_relative_url(thumbnail, base_uri, base_url_str, config.media_proxy, "thumbnail.webp")
  end
  
  if resolved_url = resolve_relative_url(result.url, base_uri, base_url_str, nil, "")
    result.url = resolved_url
  end
end

# Application bootstrap and configuration loading
def initialize_application
  config_path = ENV["SUMMALY_CONFIG_PATH"]? || "config.json"

  # Create default configuration if none exists
  unless File.exists?(config_path)
    default_config = ConfigFile.new
    File.write(config_path, default_config.to_pretty_json)
    Log.info { "Created default configuration at #{config_path}" }
  end

  config = ConfigFile.from_json(File.read(config_path))
  rate_limiter = RateLimit.new

  {config, rate_limiter}
end

# Main application entry point
config, rate_limiter = initialize_application

# Configure Kemal web server
Kemal.config.host_binding = config.bind_addr.split(':')[0]
Kemal.config.port = config.bind_addr.split(':')[1].to_i

get "/*" do |env|
  params = RequestParams.new(url: "")
  
  # Parse query parameters
  env.params.query.each do |key, value|
    case key
    when "url"
      params.url = value
    when "lang"
      params.lang = value
    when "userAgent"
      params.user_agent = value
    when "responseTimeout"
      params.response_timeout = value.to_u32?
    when "contentLengthLimit"
      params.content_length_limit = value.to_u32?
    end
  end
  
  # Log request
  Log.info { "#{Time.utc.to_rfc3339} #{params.url} lang:#{params.lang} response_timeout:#{params.response_timeout} content_length_limit:#{params.content_length_limit} user_agent:#{params.user_agent}" }
  
  # Handle special URLs
  if params.url.starts_with?("coffee://")
    env.response.headers["X-Proxy-Error"] = "I'm a teapot"
    config.append_headers_to(env.response.headers)
    env.response.status_code = 418
    next
  end
  
  # Check rate limiting
  unless rate_limiter.request_allowed?(params.url)
    retry_count = 0
    while retry_count < 3
      sleep 1.second
      break if rate_limiter.request_allowed?(params.url)
      retry_count += 1
    end
    
    if retry_count >= 3
      env.response.headers["Cache-Control"] = "public, max-age=30"
      config.append_headers_to(env.response.headers)
      env.response.status_code = 429
      next
    end
  end
  
  begin
    # Create HTTP client
    uri = URI.parse(params.url)
    unless uri.host
      env.response.headers["X-Proxy-Error"] = "Invalid URL"
      config.append_headers_to(env.response.headers)
      env.response.status_code = 400
      next
    end
    
    client = HTTP::Client.new(uri)
    client.connect_timeout = (config.timeout / 1000).seconds
    client.read_timeout = (params.response_timeout || config.timeout.to_u32).seconds
    
    # Set headers
    headers = HTTP::Headers.new
    headers["User-Agent"] = params.user_agent || config.user_agent
    if lang = params.lang
      headers["Accept-Language"] = lang
    end
    
    # Make request
    response = client.get(uri.full_path, headers)
    
    unless response.status_code == 200
      env.response.headers["X-Proxy-Error"] = "HTTP #{response.status_code}"
      config.append_headers_to(env.response.headers)
      env.response.status_code = 502
      next
    end
    
    # Load response body
    content_limit = (params.content_length_limit || config.max_size).to_u64
    html_content = process_html_content(response, content_limit)
    
    unless html_content
      env.response.headers["X-Proxy-Error"] = "Content too large or load failed"
      config.append_headers_to(env.response.headers)
      env.response.status_code = 502
      next
    end
    
    # Parse metadata
    result = extract_metadata(html_content, uri, config, client, params)
    
    # Return JSON response
    env.response.content_type = "application/json"
    env.response.headers["Cache-Control"] = "public, max-age=1800"
    config.append_headers_to(env.response.headers)
    
    result.to_json
    
  rescue ex
    Log.error { "Error processing #{params.url}: #{ex.message}" }
    env.response.headers["X-Proxy-Error"] = ex.message || "Unknown error"
    config.append_headers_to(env.response.headers)
    env.response.status_code = 500
  ensure
    rate_limiter.complete_request(params.url)
  end
end

# Start server
Log.info { "Starting Summaly.cr on #{config.bind_addr}" }
Kemal.run
