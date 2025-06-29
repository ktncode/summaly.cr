# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2025 Kotone <git@ktn.works>

require "kemal"
require "json"
require "http/client"
require "xml"
require "uri"
require "log"
require "compress/gzip"

struct ConfigFile
  include JSON::Serializable

  property bind_addr : String = "0.0.0.0:3000"
  property timeout : UInt64 = 5000_u64
  property user_agent : String = "Summaly.cr/1.0 (+https://github.com/ktncode/summaly.cr)"
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
class SummalyPlayer
  include JSON::Serializable

  property url : String? = nil
  property width : Float64? = nil
  property height : Float64? = nil
  property allow : Array(String) = [] of String
  
  def initialize
    @url = nil
    @width = nil
    @height = nil
    @allow = [] of String
  end
end

# Primary API response structure
class SummalyResult
  include JSON::Serializable

  property url : String
  property title : String? = nil
  property icon : String? = nil
  property description : String? = nil
  property thumbnail : String? = nil
  property sitename : String? = nil
  property player : JSON::Any?
  property sensitive : Bool = false
  @[JSON::Field(key: "activityPub")]
  property activity_pub : String? = nil
  property oembed : OEmbed? = nil
  
  def initialize(@url : String)
    @player = nil
  end
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
    # Remove only null characters and dangerous control characters, keep normal whitespace
    .gsub(/[\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0B\x0C\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x7F]/, "")
    # Convert multiple newlines/tabs to single spaces
    .gsub(/[\n\r\t]+/, " ")
    # Normalize multiple spaces
    .gsub(/\s+/, " ")
    .strip
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
  # Get response body directly
  body = response.body
  
  # Check content size limit
  if body.bytesize > size_limit
    return nil
  end
  
  # Check for gzip encoding and decompress if needed
  content_encoding = response.headers["Content-Encoding"]?
  Log.info { "Content-Encoding header: #{content_encoding}" }
  
  if content_encoding.try(&.downcase) == "gzip"
    Log.info { "Decompressing gzip content" }
    begin
      decompressed_body = Compress::Gzip::Reader.open(IO::Memory.new(body)) do |gzip|
        gzip.gets_to_end
      end
      body = decompressed_body
      Log.info { "Decompressed content length: #{body.size}" }
    rescue ex
      Log.warn { "Failed to decompress gzip: #{ex.message}, using original body" }
      # gzip解凍に失敗した場合は元のbodyをそのまま使用
    end
  else
    Log.info { "No gzip compression detected, using body as-is" }
  end
  
  # Convert to bytes for encoding detection
  bytes = body.to_slice
  
  # Extract charset information from meta tags first (before string conversion)
  charset = extract_charset_from_bytes(bytes)
  Log.info { "Detected charset: #{charset}" } if charset
  
  # Convert to string with detected encoding
  detect_and_convert_encoding_with_charset(bytes, charset)
end

# Character encoding detection and conversion with better error handling
private def detect_and_convert_encoding(bytes : Bytes) : String
  # First, try to read as UTF-8 with strict validation
  begin
    content = String.new(bytes, "UTF-8")
    # Test if the string is valid UTF-8 by attempting a simple operation
    content.size
    Log.info { "Content is valid UTF-8" }
    return content
  rescue
    Log.info { "Content is not valid UTF-8, trying fallback encoding" }
  end
  
  # Try with UTF-8 invalid skip first
  begin
    content = String.new(bytes, "UTF-8", invalid: :skip)
    if content.includes?("<html") || content.includes?("<HTML")
      Log.info { "UTF-8 with invalid skip worked" }
      return ensure_valid_utf8(content)
    end
  rescue
    Log.info { "UTF-8 with invalid skip failed" }
  end
  
  # Fallback to Latin-1
  begin
    content = String.new(bytes, "ISO-8859-1")
    Log.info { "Using ISO-8859-1 fallback" }
  rescue
    # Last resort: force UTF-8 conversion
    content = String.new(bytes, "UTF-8", invalid: :skip)
    Log.info { "Using forced UTF-8 conversion" }
  end
  
  # Look for charset declarations in HTML meta tags with error handling
  charset_patterns = [
    /<meta[^>]+charset\s*=\s*["']?([^"'>\s]+)/i,
    /<meta[^>]+http-equiv\s*=\s*["']?content-type["']?[^>]*charset\s*=\s*([^"';\s]+)/i
  ]
  
  charset_patterns.each do |pattern|
    begin
      if match = content.match(pattern)
        charset = match[1].downcase
        Log.info { "Found charset declaration: #{charset}" }
        return handle_charset_conversion(bytes, charset)
      end
    rescue
      # Continue if regex fails due to encoding issues
      next
    end
  end
  
  # Ensure the final content is valid UTF-8
  ensure_valid_utf8(content)
end

private def ensure_valid_utf8(content : String) : String
  # Remove only null characters and dangerous control characters
  # Keep Unicode replacement characters (�) and normal whitespace
  content
    .gsub(/[\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0B\x0C\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x7F]/, "")
    .strip
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
  
  # Create result structure using new constructor
  result = SummalyResult.new(request_params.url)
  
  # Create player data structure
  player_data = SummalyPlayer.new

  begin
    Log.info { "Starting HTML metadata extraction, content length: #{html_content.size}" }
    
    # HTMLコンテンツが大きすぎる場合は制限する（メモリエラー回避）
    if html_content.size > 1_000_000  # 1MBを超える場合
      Log.warn { "HTML content too large (#{html_content.size} bytes), truncating to 1MB" }
      html_content = html_content[0...1_000_000]
    end
    
    # より安定したHTMLパース手法：<head>セクションを抽出してパースする
    extract_head_section_and_parse(html_content, result, player_data, base_uri, base_url_str, config, http_client)
    
    Log.info { "Before finalize_result - player: #{result.player.inspect}" }
    finalize_result(result, player_data, base_uri, base_url_str, config)
    Log.info { "After finalize_result - player: #{result.player.inspect}" }
    
  rescue ex
    Log.warn { "HTML metadata extraction failed: #{ex.message}" }
  end
  
  result
end

private def parse_html_document(html : String)
  Log.info { "Parsing HTML document, length: #{html.size}" }
  
  # HTMLコンテンツが空でないかチェック
  return nil if html.empty?
  
  # HTMLコンテンツのプレビューを安全に表示（500文字まで）
  preview_length = [500, html.size].min
  Log.info { "HTML content preview: #{html[0...preview_length]}..." }
  
  begin
    # より基本的なパースオプションを使用してメモリエラーを回避
    document = XML.parse_html(html, XML::HTMLParserOptions::RECOVER)
    Log.info { "HTML parsing completed successfully" }
    
    # ドキュメント構造を安全にデバッグ
    if document && (root = document.root)
      Log.info { "Document root element: #{root.name}" }
      
      # 要素数を安全にカウント
      begin
        all_elements = document.xpath_nodes("//*")
        Log.info { "Total elements found: #{all_elements.size}" }
        
        # 最初の数個の要素名を安全に取得
        if all_elements.size > 0
          first_count = [5, all_elements.size].min  # 10個から5個に減らして安全性を向上
          element_names = [] of String
          (0...first_count).each do |i|
            element_names << all_elements[i].name
          end
          Log.info { "First #{first_count} elements: #{element_names.join(", ")}" }
        end
      rescue ex
        Log.warn { "Failed to analyze document structure: #{ex.message}" }
      end
    else
      Log.warn { "Document or root is nil after parsing" }
      return nil
    end
    
    document
  rescue ex
    Log.warn { "HTML parsing failed: #{ex.message}" }
    nil
  end
end

private def extract_title(document, result : SummalyResult)
  return unless document
  if title_element = document.xpath_node("//title")
    title_text = title_element.text.strip
    result.title = title_text unless title_text.empty?
  end
end

private def process_meta_tags(document, result : SummalyResult, player_data : SummalyPlayer)
  return unless document
  document.xpath_nodes("//meta").each do |meta_tag|
    process_meta_name_attributes(meta_tag, result)
    process_opengraph_properties(meta_tag, result, player_data)
  end
end

private def process_meta_name_attributes(meta_tag, result : SummalyResult)
  name = meta_tag["name"]?
  content = meta_tag["content"]?.try { |c| decode_html_entities(c.strip) }
  
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
  property = meta_tag["property"]?
  content = meta_tag["content"]?.try { |c| decode_html_entities(c.strip) }
  
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
  return unless document
  Log.info { "Processing link tags..." }
  
  # 複数の方法でリンクタグを検索
  link_nodes_1 = document.xpath_nodes("//link")
  Log.info { "Found #{link_nodes_1.size} link nodes with XPath //link" }
  
  link_nodes_2 = document.xpath_nodes("//html//link")
  Log.info { "Found #{link_nodes_2.size} link nodes with XPath //html//link" }
  
  link_nodes_3 = document.xpath_nodes("//*[local-name()='link']")
  Log.info { "Found #{link_nodes_3.size} link nodes with XPath //*[local-name()='link']" }
  
  # headタグも複数の方法で検索
  head_nodes_1 = document.xpath_nodes("//head")
  Log.info { "Found #{head_nodes_1.size} head nodes with XPath //head" }
  
  head_nodes_2 = document.xpath_nodes("//*[local-name()='head']")
  Log.info { "Found #{head_nodes_2.size} head nodes with XPath //*[local-name()='head']" }
  
  # 最初に見つかったリンクタグを使用
  link_nodes = link_nodes_1.size > 0 ? link_nodes_1 : (link_nodes_2.size > 0 ? link_nodes_2 : link_nodes_3)
  
  link_count = 0
  link_nodes.each do |link_tag|
    rel = link_tag["rel"]?
    href = link_tag["href"]?.try { |h| decode_html_entities(h.strip) }
    link_type = link_tag["type"]?
    link_count += 1
    
    Log.info { "Link #{link_count}: rel=#{rel}, type=#{link_type}, href=#{href ? href[0..100] : "nil"}" }
    
    next unless rel && href
    
    process_icon_links(rel, href, result)
    process_oembed_links(rel, link_type, href, result, base_uri, base_url_str, config, client)
  end
  Log.info { "Total link tags processed: #{link_count}" }
end

private def process_icon_links(rel : String, href : String, result : SummalyResult)
  case rel
  when "shortcut icon"  then result.icon ||= href
  when "icon"           then result.icon = href
  when "apple-touch-icon" then result.thumbnail ||= href
  end
end

private def process_oembed_links(rel : String, link_type : String?, href : String, result : SummalyResult, base_uri : URI, base_url_str : String, config : ConfigFile, client : HTTP::Client)
  Log.info { "Processing link: rel=#{rel}, type=#{link_type}, href=#{href}" }
  
  # YouTubeはtype="application/json+oembed"または"text/xml+oembed"を使用する場合がある
  oembed_types = ["application/json+oembed", "text/xml+oembed"]
  return unless rel == "alternate" && link_type && oembed_types.includes?(link_type)
  
  Log.info { "Found OEmbed link: #{href}" }
  oembed_url = resolve_relative_url(href, base_uri, base_url_str, nil, "")
  return unless oembed_url
  
  Log.info { "Fetching OEmbed data from: #{oembed_url}" }
  fetch_oembed_data(oembed_url, result, config, client)
end

private def fetch_oembed_data(oembed_url : String, result : SummalyResult, config : ConfigFile, client : HTTP::Client)
  Log.info { "Fetching OEmbed from: #{oembed_url}" }
  oembed_response = client.get(oembed_url)
  Log.info { "OEmbed response status: #{oembed_response.status_code}" }
  return unless oembed_response.status_code == 200
  
  content = process_html_content(oembed_response, config.max_size.to_u64)
  return unless content
  
  Log.info { "OEmbed content: #{content[0..200]}..." }
  
  # Determine OEmbed format and parse accordingly
  oembed_data = parse_oembed_content(content)
  return unless oembed_data
  
  result.oembed = oembed_data
  Log.info { "OEmbed data: type=#{oembed_data.type}, html present=#{!oembed_data.html.nil?}" }
  
  # Extract security-conscious iframe attributes
  extract_safe_iframe_attributes(oembed_data, result)
rescue ex
  Log.warn { "OEmbed fetch failed: #{ex.message}" }
end

private def parse_oembed_content(content : String) : OEmbed?
  # Trim whitespace and check format
  trimmed_content = content.strip
  
  if trimmed_content.starts_with?('<')
    # XML format
    Log.info { "Parsing OEmbed as XML format" }
    parse_oembed_xml(trimmed_content)
  else
    # JSON format
    Log.info { "Parsing OEmbed as JSON format" }
    begin
      OEmbed.from_json(trimmed_content)
    rescue ex
      Log.warn { "Failed to parse OEmbed JSON: #{ex.message}" }
      nil
    end
  end
rescue ex
  Log.warn { "Failed to parse OEmbed content: #{ex.message}" }
  nil
end

private def parse_oembed_xml(xml_content : String) : OEmbed?
  begin
    document = XML.parse(xml_content)
    
    # Extract basic OEmbed fields from XML
    type = extract_xml_text(document, "//type") || "rich"
    version = extract_xml_text(document, "//version") || "1.0"
    title = extract_xml_text(document, "//title")
    description = extract_xml_text(document, "//description")
    author_name = extract_xml_text(document, "//author_name")
    author_url = extract_xml_text(document, "//author_url")
    provider_name = extract_xml_text(document, "//provider_name")
    provider_url = extract_xml_text(document, "//provider_url")
    cache_age = extract_xml_text(document, "//cache_age").try(&.to_i64?)
    thumbnail_url = extract_xml_text(document, "//thumbnail_url")
    thumbnail_width = extract_xml_text(document, "//thumbnail_width").try(&.to_i64?)
    thumbnail_height = extract_xml_text(document, "//thumbnail_height").try(&.to_i64?)
    
    # Extract dimensions
    width = extract_xml_text(document, "//width").try(&.to_i64?)
    height = extract_xml_text(document, "//height").try(&.to_i64?)
    
    # Extract HTML content (for video/rich types)
    html = extract_xml_text(document, "//html")
    
    # Extract URL (for photo type)
    url = extract_xml_text(document, "//url")
    
    Log.info { "Parsed XML OEmbed: type=#{type}, width=#{width}, height=#{height}, html present=#{!html.nil?}" }
    
    # Create OEmbed object using JSON building since we can't use new directly
    json_builder = JSON.build do |json|
      json.object do
        json.field "type", type
        json.field "version", version
        json.field "title", title if title
        json.field "description", description if description
        json.field "author_name", author_name if author_name
        json.field "author_url", author_url if author_url
        json.field "provider_name", provider_name if provider_name
        json.field "provider_url", provider_url if provider_url
        json.field "cache_age", cache_age if cache_age
        json.field "thumbnail_url", thumbnail_url if thumbnail_url
        json.field "thumbnail_width", thumbnail_width if thumbnail_width
        json.field "thumbnail_height", thumbnail_height if thumbnail_height
        json.field "width", width if width
        json.field "height", height if height
        json.field "html", html if html
        json.field "url", url if url
      end
    end
    
    OEmbed.from_json(json_builder)
  rescue ex
    Log.warn { "Failed to parse OEmbed XML: #{ex.message}" }
    nil
  end
end

private def extract_xml_text(document, xpath : String) : String?
  nodes = document.xpath_nodes(xpath)
  return nil if nodes.empty?
  
  text = nodes.first.content.strip
  text.empty? ? nil : text
end

private def extract_safe_iframe_attributes(oembed_data : OEmbed, result : SummalyResult)
  return unless html_content = oembed_data.html
  Log.info { "Extracting iframe from OEmbed HTML: #{html_content[0..200]}..." }

  # 既にplayerが設定されている場合はスキップ
  if player = result.player
    if player.as_h?.try(&.has_key?("url"))
      Log.info { "Player already set, skipping OEmbed iframe extraction" }
      return
    end
  end

  # OEmbedのwidth/heightを優先的に使用
  player_json = Hash(String, JSON::Any).new
  
  # OEmbedのwidth/heightがあればそれを使用
  if width = oembed_data.width
    player_json["width"] = JSON::Any.new(width)
  end
  
  if height = oembed_data.height
    player_json["height"] = JSON::Any.new(height)
  end

  # セーフリスト：安全なiframe機能のみ許可
  safe_features = ["autoplay", "clipboard-write", "fullscreen", "encrypted-media", "picture-in-picture", "web-share"]
  allow_features = [] of String

  # iframeタグからsrc, allow属性を抽出
  if iframe_match = html_content.match(/<iframe[^>]+>/i)
    iframe_tag = iframe_match[0]
    
    # src属性を抽出
    if src_match = iframe_tag.match(/src\s*=\s*["']([^"']+)["']/i)
      src = src_match[1]
      player_json["url"] = JSON::Any.new(src)
      Log.info { "Extracted iframe src: #{src}" }
    end
    
    # allow属性を抽出してセーフリストでフィルタ
    if allow_match = iframe_tag.match(/allow\s*=\s*["']([^"']+)["']/i)
      allow_value = allow_match[1]
      allow_value.split(";").each do |feature|
        feature = feature.strip
        if safe_features.includes?(feature)
          allow_features << feature
        end
      end
      Log.info { "Extracted iframe allow: #{allow_features}" }
    end
  end

  # allowリストを設定
  player_json["allow"] = JSON::Any.new(allow_features.map { |f| JSON::Any.new(f) })

  # playerにURLがある場合のみ設定
  if player_json["url"]?
    result.player = JSON::Any.new(player_json)
    Log.info { "Set player data: #{result.player}" }
    Log.info { "Player set successfully, result.player is now: #{result.player.inspect}" }
    Log.info { "Player type: #{result.player.class}" }
  else
    Log.warn { "No iframe src found in OEmbed HTML, player not set" }
  end
end

private def finalize_result(result : SummalyResult, player_data : SummalyPlayer, base_uri : URI, base_url_str : String, config : ConfigFile)
  Log.info { "finalize_result called - player at start: #{result.player.inspect}" }
  Log.info { "player_data at start: url=#{player_data.url}, width=#{player_data.width}, height=#{player_data.height}" }
  
  # OEmbedのplayerが優先。なければOpenGraph由来のplayer_dataを使う。
  # result.playerにURLが設定されていない場合のみOpenGraphデータを使用
  
  # playerが設定されているかチェック
  player_has_url = result.player.try { |p| p.as_h.has_key?("url") && !p.as_h["url"].as_s?.try(&.empty?) } || false
  Log.info { "player_has_url check result: #{player_has_url}" }
  
  if !player_has_url && player_data.url
    # OpenGraph由来のplayerデータをセット
    player_json = Hash(String, JSON::Any).new
    player_json["url"] = JSON::Any.new(player_data.url.not_nil!)
    if width = player_data.width
      player_json["width"] = JSON::Any.new(width)
    end
    if height = player_data.height
      player_json["height"] = JSON::Any.new(height)
    end
    player_json["allow"] = JSON::Any.new(player_data.allow.map { |f| JSON::Any.new(f) })
    
    result.player = JSON::Any.new(player_json)
    Log.info { "Set OpenGraph player data: #{result.player}" }
  elsif player_has_url
    Log.info { "Using OEmbed player data: #{result.player}" }
  else
    Log.info { "No player data available" }
  end

  # Set default icon
  result.icon ||= "#{base_url_str}/favicon.ico"

  # Resolve all relative URLs
  resolve_result_urls(result, base_uri, base_url_str, config)
  
  Log.info { "finalize_result finished - final player: #{result.player.inspect}" }
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
    default_config_json = JSON.build(indent: "  ") do |json|
      json.object do
        json.field "bind_addr", "0.0.0.0:3000"
        json.field "timeout", 5000
        json.field "user_agent", "https://github.com/ktncode/summaly.cr"
        json.field "max_size", 2097152
        json.field "proxy", nil
        json.field "media_proxy", nil
        json.field "append_headers" do
          json.array do
            json.string "Content-Security-Policy:default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'"
            json.string "Access-Control-Allow-Origin:*"
          end
        end
      end
    end
    File.write(config_path, default_config_json)
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
  # Initialize request parameters
  url = ""
  lang : String? = nil
  user_agent : String? = nil
  response_timeout : UInt32? = nil
  content_length_limit : UInt32? = nil
  
  # Parse query parameters
  env.params.query.each do |key, value|
    case key
    when "url"
      url = value
    when "lang"
      lang = value
    when "userAgent"
      user_agent = value
    when "responseTimeout"
      response_timeout = value.to_u32?
    when "contentLengthLimit"
      content_length_limit = value.to_u32?
    end
  end
  
  # Log request
  Log.info { "#{Time.utc.to_rfc3339} #{url} lang:#{lang} response_timeout:#{response_timeout} content_length_limit:#{content_length_limit} user_agent:#{user_agent}" }
  
  # Check if URL is provided
  if url.empty?
    env.response.headers["X-Proxy-Error"] = "URL parameter is required"
    config.append_headers_to(env.response.headers)
    env.response.status_code = 400
    next
  end
  
  # Validate URL format
  unless url.starts_with?("http://") || url.starts_with?("https://")
    env.response.headers["X-Proxy-Error"] = "URL must start with http:// or https://"
    config.append_headers_to(env.response.headers)
    env.response.status_code = 400
    next
  end
  
  # Handle special URLs
  if url.starts_with?("coffee://")
    env.response.headers["X-Proxy-Error"] = "I'm a teapot"
    config.append_headers_to(env.response.headers)
    env.response.status_code = 418
    next
  end
  
  # Check rate limiting
  unless rate_limiter.request_allowed?(url)
    retry_count = 0
    while retry_count < 3
      sleep 1.second
      break if rate_limiter.request_allowed?(url)
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
    uri = URI.parse(url)
    unless uri.host
      env.response.headers["X-Proxy-Error"] = "Invalid URL"
      config.append_headers_to(env.response.headers)
      env.response.status_code = 400
      next
    end
    
    client = HTTP::Client.new(uri)
    timeout_ms = [config.timeout, (response_timeout || config.timeout.to_u32).to_u64].min
    client.connect_timeout = (timeout_ms / 1000).seconds
    client.read_timeout = (timeout_ms / 1000).seconds
    
    # Set headers
    headers = HTTP::Headers.new
    
    # Special User-Agent for X.com/Twitter.com
    if uri.host == "twitter.com" || uri.host == "x.com"
      headers["User-Agent"] = "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"
    else
      headers["User-Agent"] = user_agent || config.user_agent
    end
    
    if lang
      headers["Accept-Language"] = lang
    end
    
    Log.info { "Making request to #{url} with headers: User-Agent=#{headers["User-Agent"]}" }
    
    # Make request with automatic redirect following
    path = uri.path || "/"
    path += "?#{uri.query}" if uri.query
    
    final_response = client.get(path, headers)
    
    Log.info { "HTTP response: #{final_response.status_code} for #{url}" }
    
    unless final_response.status_code == 200
      Log.warn { "Non-200 response: #{final_response.status_code} for #{url}" }
      env.response.headers["X-Proxy-Error"] = "HTTP #{final_response.status_code}"
      config.append_headers_to(env.response.headers)
      env.response.status_code = 502
      next
    end
    
    # Load response body
    content_limit = (content_length_limit || config.max_size).to_u64
    html_content = process_html_content(final_response, content_limit)
    
    unless html_content
      env.response.headers["X-Proxy-Error"] = "Content too large or load failed"
      config.append_headers_to(env.response.headers)
      env.response.status_code = 502
      next
    end
    
    # Create RequestParams for extract_metadata
    request_params = RequestParams.from_json(JSON.build do |json|
      json.object do
        json.field "url", url
        json.field "lang", lang
        json.field "userAgent", user_agent
        json.field "responseTimeout", response_timeout
        json.field "contentLengthLimit", content_length_limit
      end
    end)
    
    # Parse metadata
    result = extract_metadata(html_content, uri, config, client, request_params)
    
    # Debug: Log player data before JSON conversion
    Log.info { "Final result before JSON conversion - player: #{result.player}" }
    if player = result.player
      Log.info { "Player has_key url? #{player.as_h.has_key?("url")}" }
      Log.info { "Player keys: #{player.as_h.keys}" }
    else
      Log.info { "Player is nil" }
    end
    
    # Return JSON response
    env.response.content_type = "application/json"
    env.response.headers["Cache-Control"] = "public, max-age=1800"
    config.append_headers_to(env.response.headers)
    
    result.to_json
    
  rescue ex
    Log.error { "Error processing #{url}: #{ex.message}" }
    Log.error { "Backtrace: #{ex.backtrace?.try(&.join("\n"))}" }
    env.response.headers["X-Proxy-Error"] = ex.message || "Unknown error"
    config.append_headers_to(env.response.headers)
    env.response.status_code = 500
  ensure
    rate_limiter.complete_request(url)
  end
end

# Start server
Log.info { "Starting Summaly.cr on #{config.bind_addr}" }
Kemal.run

# Extract head section and parse it for better stability
private def extract_head_section_and_parse(html_content : String, result : SummalyResult, player_data : SummalyPlayer, base_uri : URI, base_url_str : String, config : ConfigFile, client : HTTP::Client)
  Log.info { "Extracting <head> section from HTML" }
  Log.info { "HTML content preview (first 1000 chars): #{html_content[0...1000]}" }
  
  # Find <head> section (case insensitive) - より柔軟な検索
  head_start_match = html_content.match(/<head[\s>]/i)
  head_end_match = html_content.match(/<\/head>/i)
  
  unless head_start_match && head_end_match
    Log.warn { "Could not find <head> section, trying alternative approach" }
    # headが見つからない場合は、HTML全体から直接メタデータを抽出
    parse_full_html_content(html_content, result, player_data, base_uri, base_url_str, config, client)
    return
  end
  
  head_start = head_start_match.end
  head_end = head_end_match.begin
  
  if head_start >= head_end
    Log.warn { "Invalid <head> section boundaries, using full HTML" }
    parse_full_html_content(html_content, result, player_data, base_uri, base_url_str, config, client)
    return
  end
  
  head_content = html_content[head_start...head_end]
  Log.info { "Extracted head section, length: #{head_content.size}" }
  
  # Parse head content using simple regex-based parsing
  parse_head_content_simple(head_content, result, player_data, base_uri, base_url_str, config, client)
end

# Simple regex-based parsing of head content
private def parse_head_content_simple(head_content : String, result : SummalyResult, player_data : SummalyPlayer, base_uri : URI, base_url_str : String, config : ConfigFile, client : HTTP::Client)
  Log.info { "Parsing head content with regex approach" }
  
  # Extract title
  if title_match = head_content.match(/<title[^>]*>(.*?)<\/title>/im)
    title_text = decode_html_entities(title_match[1].strip)
    result.title = title_text unless title_text.empty?
    Log.info { "Found title: #{title_text}" }
  end
  
  # Extract meta tags
  meta_pattern = /<meta[^>]+>/i
  head_content.scan(meta_pattern) do |meta_match|
    meta_tag = meta_match[0]
    process_meta_tag_simple(meta_tag, result, player_data)
  end
  
  # Extract link tags
  link_pattern = /<link[^>]+>/i
  head_content.scan(link_pattern) do |link_match|
    link_tag = link_match[0]
    process_link_tag_simple(link_tag, result, base_uri, base_url_str, config, client)
  end
end

# Process meta tag using simple attribute extraction
private def process_meta_tag_simple(meta_tag : String, result : SummalyResult, player_data : SummalyPlayer)
  # Extract attributes using regex
  name = extract_attribute(meta_tag, "name")
  property = extract_attribute(meta_tag, "property")
  content = extract_attribute(meta_tag, "content")
  
  return unless content
  content = decode_html_entities(content.strip)
  
  # Process name attributes
  if name
    case name.downcase
    when "msapplication-tooltip"
      result.description ||= content
    when "application-name"
      result.sitename ||= content
      result.title ||= content
    when "description"
      result.description ||= content
    end
  end
  
  # Process OpenGraph properties
  if property
    case property.downcase
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
end

# Process link tag using simple attribute extraction
private def process_link_tag_simple(link_tag : String, result : SummalyResult, base_uri : URI, base_url_str : String, config : ConfigFile, client : HTTP::Client)
  rel = extract_attribute(link_tag, "rel")
  href = extract_attribute(link_tag, "href")
  link_type = extract_attribute(link_tag, "type")
  
  return unless href
  
  href = decode_html_entities(href.strip)
  
  # Process ActivityPub JSON-LD links (Misskey/Mastodon support)
  if link_type && link_type.downcase == "application/activity+json"
    Log.info { "Found ActivityPub JSON-LD link: #{href}" }
    activitypub_url = resolve_relative_url(href, base_uri, base_url_str, nil, "")
    if activitypub_url
      result.activity_pub = activitypub_url
      Log.info { "Set ActivityPub URL: #{activitypub_url}" }
    end
    return
  end
  
  return unless rel
  
  # Process icon links
  case rel.downcase
  when "shortcut icon"  then result.icon ||= href
  when "icon"           then result.icon = href
  when "apple-touch-icon" then result.thumbnail ||= href
  when "alternate"
    if link_type && (link_type.downcase == "application/json+oembed" || link_type.downcase == "text/xml+oembed")
      Log.info { "Found OEmbed link: #{href}" }
      oembed_url = resolve_relative_url(href, base_uri, base_url_str, nil, "")
      if oembed_url
        Log.info { "Fetching OEmbed data from: #{oembed_url}" }
        fetch_oembed_data(oembed_url, result, config, client)
      end
    end
  end
end

# Extract attribute value from HTML tag
private def extract_attribute(tag : String, attr_name : String) : String?
  # Pattern to match attribute="value" or attribute='value'
  pattern = /#{Regex.escape(attr_name)}\s*=\s*["']([^"']*?)["']/i
  if match = tag.match(pattern)
    return match[1]
  end
  
  # Pattern to match attribute=value (without quotes)
  pattern = /#{Regex.escape(attr_name)}\s*=\s*([^\s>]+)/i
  if match = tag.match(pattern)
    return match[1]
  end
  
  nil
end

# Parse full HTML content when head section is not found
private def parse_full_html_content(html_content : String, result : SummalyResult, player_data : SummalyPlayer, base_uri : URI, base_url_str : String, config : ConfigFile, client : HTTP::Client)
  Log.info { "Parsing full HTML content as fallback" }
  
  # Extract title from anywhere in the document
  if title_match = html_content.match(/<title[^>]*>(.*?)<\/title>/im)
    title_text = decode_html_entities(title_match[1].strip)
    result.title = title_text unless title_text.empty?
    Log.info { "Found title: #{title_text}" }
  else
    Log.warn { "No title found in HTML" }
  end
  
  # Extract meta tags from full document
  meta_count = 0
  meta_pattern = /<meta[^>]+>/i
  html_content.scan(meta_pattern) do |meta_match|
    meta_tag = meta_match[0]
    meta_count += 1
    process_meta_tag_simple(meta_tag, result, player_data)
  end
  Log.info { "Found #{meta_count} meta tags" }
  
  # Extract link tags from full document
  link_count = 0
  link_pattern = /<link[^>]+>/i
  html_content.scan(link_pattern) do |link_match|
    link_tag = link_match[0]
    link_count += 1
    process_link_tag_simple(link_tag, result, base_uri, base_url_str, config, client)
  end
  Log.info { "Found #{link_count} link tags" }
end

# Extract charset from raw bytes by looking for meta tags
private def extract_charset_from_bytes(bytes : Bytes) : String?
  # Look for meta charset patterns in raw bytes
  meta_start = "<meta ".bytes
  meta_start_upper = "<META ".bytes
  
  i = 0
  meta_content = [] of UInt8
  in_meta_tag = false
  
  bytes.each do |byte|
    if !in_meta_tag
      # Check for start of meta tag
      if (i < meta_start.size && (byte == meta_start[i] || byte == meta_start_upper[i]))
        i += 1
        if i == meta_start.size
          in_meta_tag = true
          meta_content.clear
        end
      else
        i = 0
      end
    else
      # Collect meta tag content until >
      if byte == '>'.ord
        # Try to extract charset from this meta tag
        if meta_content.size > 0
          meta_str = String.new(Slice.new(meta_content.to_unsafe, meta_content.size))
          if charset = parse_charset_from_meta(meta_str)
            return charset
          end
        end
        in_meta_tag = false
        i = 0
        meta_content.clear
      else
        meta_content << byte
      end
    end
  end
  
  nil
end

# Parse charset from meta tag content
private def parse_charset_from_meta(meta_content : String) : String?
  # Look for charset= pattern
  if match = meta_content.match(/charset\s*=\s*["']?([^"'\s>]+)/i)
    return match[1].downcase
  end
  
  # Look for http-equiv content-type
  if meta_content.match(/http-equiv\s*=\s*["']?content-type["']?/i)
    if match = meta_content.match(/content\s*=\s*["']?[^"']*?charset\s*=\s*([^"';\s]+)/i)
      return match[1].downcase
    end
  end
  
  nil
end

# Enhanced encoding detection with charset hint
private def detect_and_convert_encoding_with_charset(bytes : Bytes, charset_hint : String?) : String
  # If we have a charset hint, try it first
  if charset_hint
    Log.info { "Trying charset hint: #{charset_hint}" }
    case charset_hint
    when "utf-8", "utf8"
      begin
        content = String.new(bytes, "UTF-8")
        Log.info { "Successfully used UTF-8 encoding" }
        return content
      rescue
        Log.info { "UTF-8 failed, trying with skip invalid" }
        begin
          content = String.new(bytes, "UTF-8", invalid: :skip)
          return ensure_valid_utf8(content)
        rescue
          Log.info { "UTF-8 with skip failed" }
        end
      end
    when "iso-8859-1", "latin-1"
      begin
        content = String.new(bytes, "ISO-8859-1")
        Log.info { "Successfully used ISO-8859-1 encoding" }
        return ensure_valid_utf8(content)
      rescue
        Log.info { "ISO-8859-1 failed" }
      end
    end
  end
  
  # Fallback to original detection method
  detect_and_convert_encoding(bytes)
end
