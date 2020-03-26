require "omniauth/strategies/oauth2"
require "uri"
require "rack/utils"

module OmniAuth
  module Strategies
    class Slack < OmniAuth::Strategies::OAuth2
      option :name, "slack"

      option :authorize_options, [:scope, :team, :redirect_uri]

      option :client_options, {
        site: "https://slack.com",
        token_url: "/api/oauth.v2.access",
      }

      option :auth_token_params, {
        mode: :query,
        param_name: "token",
      }

      uid {
        bot_info[:id]
      }

      info do
        hash = {
          authed_user_info: user_info,
          bot_info: bot_info,
          team_info: team_info,
          web_hook_info: web_hook_info,
        }

        hash
      end

      def authed_user_info
        url = URI.parse("/api/users.info")
        url.query = Rack::Utils.build_query(
          user: access_tokens.params.dig("authed_user", "id"),
        )
        url = url.to_s

        @user_info ||= access_token.get(url).parsed
      end

      def team_info
        @team_info ||= access_token.get("/api/team.info").parsed
      end

      def web_hook_info
        return {} unless incoming_webhook_allowed?
        access_token.params["incoming_webhook"]
      end

      def bot_info
        { id: access_token.params["bot_user_id"] }
      end

      def incoming_webhook_allowed?
        return false unless options["scope"]
        webhooks_scopes = ["incoming-webhook"]
        scopes = options["scope"].split(",")
        (scopes & webhooks_scopes).any?
      end

      def callback_url
        full_host + script_name + callback_path
      end
    end
  end
end
