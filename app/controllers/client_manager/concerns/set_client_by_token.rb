module ClientManager
  module Concerns
    module SetClientByToken
      extend ActiveSupport::Concern

      included do
        before_action :set_client
        helper_method :current_client if respond_to?(:helper_method)
      end

      def unauthorized
        head 401
      end

      private

      def set_client
        client_token = request.headers['HTTP_CLIENT_TOKEN'] ||
                       params['client-token']
        return unauthorized if client_token.blank?

        begin
          decoded = JWT.decode(
            client_token, ClientManager.token_secret, true, algorithm: 'HS256'
          )
        rescue JWT::DecodeError
          return unauthorized
        end

        @current_client = ClientManager::Client.find_by(
          id: decoded[0]['client_id']
        )
        unauthorized unless @current_client
      end

      def current_client
        @current_client
      end
    end
  end
end
