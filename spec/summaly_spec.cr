# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2025 Kotone <git@ktn.works>

require "./spec_helper"
require "../src/main"

describe "Summaly.cr" do
  describe "decode_html_entities" do
    it "decodes basic HTML entities" do
      decode_html_entities("&amp;").should eq("&")
      decode_html_entities("&lt;").should eq("<")
      decode_html_entities("&gt;").should eq(">")
      decode_html_entities("&quot;").should eq("\"")
      decode_html_entities("&#39;").should eq("'")
      decode_html_entities("&nbsp;").should eq(" ")
    end

    it "handles mixed entities" do
      decode_html_entities("Hello &amp; &lt;world&gt;!").should eq("Hello & <world>!")
    end
  end

  describe "resolve_relative_url" do
    it "resolves protocol-relative URLs" do
      base_url = URI.parse("https://example.com/path")
      base_url_str = "https://example.com"
      
      result = resolve_relative_url("//cdn.example.com/image.png", base_url, base_url_str, nil, "")
      result.should eq("https://cdn.example.com/image.png")
    end

    it "resolves absolute paths" do
      base_url = URI.parse("https://example.com/path")
      base_url_str = "https://example.com"
      
      result = resolve_relative_url("/images/logo.png", base_url, base_url_str, nil, "")
      result.should eq("https://example.com/images/logo.png")
    end

    it "resolves relative paths" do
      base_url = URI.parse("https://example.com/articles/")
      base_url_str = "https://example.com"
      
      result = resolve_relative_url("../images/logo.png", base_url, base_url_str, nil, "")
      result.should eq("https://example.com/images/logo.png")
    end

    it "handles media proxy" do
      base_url = URI.parse("https://example.com")
      base_url_str = "https://example.com"
      
      result = resolve_relative_url("https://example.com/image.jpg", base_url, base_url_str, "https://proxy.com/", "thumb.webp")
      result.should eq("https://proxy.com/thumb.webp?url=https%3A//example.com/image.jpg")
    end
  end

  describe "ConfigFile" do
    it "creates from JSON" do
      json = %({
        "bind_addr": "0.0.0.0:3000",
        "timeout": 5000,
        "user_agent": "Test Agent",
        "max_size": 1048576,
        "proxy": null,
        "media_proxy": null,
        "append_headers": []
      })
      config = ConfigFile.from_json(json)
      config.bind_addr.should eq("0.0.0.0:3000")
      json.should contain("bind_addr")
      json.should contain("timeout")
    end

    it "deserializes from JSON" do
      json = %({"bind_addr":"localhost:8080","timeout":3000,"user_agent":"test","max_size":1048576,"proxy":null,"media_proxy":null,"append_headers":[]})
      config = ConfigFile.from_json(json)
      config.bind_addr.should eq("localhost:8080")
      config.timeout.should eq(3000)
    end
  end

  describe "RateLimit" do
    it "allows requests under limit" do
      rate_limiter = RateLimit.new
      rate_limiter.request_allowed?("https://example.com").should be_true
      rate_limiter.request_allowed?("https://example.com").should be_true
      rate_limiter.request_allowed?("https://example.com").should be_true
    end

    it "blocks requests over limit" do
      rate_limiter = RateLimit.new
      3.times { rate_limiter.request_allowed?("https://example.com") }
      rate_limiter.request_allowed?("https://example.com").should be_false
    end

    it "handles different hosts separately" do
      rate_limiter = RateLimit.new
      3.times { rate_limiter.request_allowed?("https://example.com") }
      rate_limiter.request_allowed?("https://other.com").should be_true
    end
  end

  describe "ActivityPub link extraction" do
    it "extracts ActivityPub link from HTML" do
      html = <<-HTML
        <html>
        <head>
          <link rel="alternate" type="application/activity+json" href="/users/alice">
          <meta property="og:title" content="Alice's Profile">
        </head>
        <body>Content</body>
        </html>
        HTML
      
      result = extract_metadata_from_html(html, "https://example.social", "https://example.social")
      result.activity_pub.should eq("https://example.social/users/alice")
    end

    it "handles absolute ActivityPub URLs" do
      html = <<-HTML
        <html>
        <head>
          <link rel="alternate" type="application/activity+json" href="https://other.social/users/bob">
        </head>
        <body>Content</body>
        </html>
        HTML
      
      result = extract_metadata_from_html(html, "https://example.social", "https://example.social")
      result.activity_pub.should eq("https://other.social/users/bob")
    end

    it "ignores ActivityPub links without proper type" do
      html = <<-HTML
        <html>
        <head>
          <link rel="alternate" href="/users/charlie">
        </head>
        <body>Content</body>
        </html>
        HTML
      
      result = extract_metadata_from_html(html, "https://example.social", "https://example.social")
      result.activity_pub.should be_nil
    end
  end
end
