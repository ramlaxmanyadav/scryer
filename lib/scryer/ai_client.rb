require "json"
require "net/http"
require "uri"

module Scryer
  # A small, provider-agnostic HTTP adapter for wiring *any* LLM into
  # AiFixSuggester — Claude, OpenAI, a self-hosted Ollama/vLLM server, or
  # anything else that takes a JSON request and returns a JSON response over
  # HTTP. Scryer ships no vendor SDKs (see the gemspec's zero-runtime-
  # dependency design); this adapter is configured with just the two pieces
  # of vendor-specific shape it needs, both plain Procs:
  #
  #   - build_request:   prompt (String) -> request body (Hash)
  #   - parse_response:  parsed JSON response (Hash) -> the model's reply (String)
  #
  # Everything else (the HTTP call, headers, timeouts) is generic. See the
  # README's "AI-assisted fix suggestions" section for ready-made
  # build_request/parse_response pairs for a couple of common APIs.
  #
  # AiFixSuggester itself doesn't require this class at all — any object
  # (or bare Proc/lambda) responding to #call(prompt) and returning a String
  # works as Scryer.configuration.ai_client. This class just saves writing
  # the HTTP plumbing by hand for the common case of a JSON chat endpoint.
  class AiClient
    def initialize(url:, build_request:, parse_response:, headers: {}, open_timeout: 5, read_timeout: 30)
      @uri = URI(url)
      @headers = { "Content-Type" => "application/json" }.merge(headers)
      @build_request = build_request
      @parse_response = parse_response
      @open_timeout = open_timeout
      @read_timeout = read_timeout
    end

    # Returns the model's reply as a String, or nil if the request failed or
    # the response couldn't be parsed. Never raises — AiFixSuggester treats
    # a nil/blank reply the same as "no client configured" and leaves the
    # finding's original suggested_fix untouched.
    def call(prompt)
      body = JSON.generate(@build_request.call(prompt))

      response = Net::HTTP.start(@uri.host, @uri.port, use_ssl: @uri.scheme == "https",
                                                        open_timeout: @open_timeout, read_timeout: @read_timeout) do |http|
        http.post(@uri.request_uri, body, @headers)
      end

      return nil unless response.is_a?(Net::HTTPSuccess)

      @parse_response.call(JSON.parse(response.body))
    rescue StandardError
      nil
    end
  end
end
