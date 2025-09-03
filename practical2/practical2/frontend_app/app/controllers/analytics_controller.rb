# frozen_string_literal: true

class AnalyticsController < ApplicationController
  before_action :check_permissions

  def index
    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    @session_hijacking = fetch_analytics(conn, "/analytics/session-hijacking")
    @impossible_travel = Array(fetch_analytics(conn, "/analytics/impossible-travel"))
    Rails.logger.debug "[Analytics] Impossible travel data: #{@impossible_travel.inspect}"

  end

  private

    def fetch_analytics(conn, path)
      response = conn.get(path) do |req|
        req.headers["Authorization"] = "Bearer #{session[:jwt]}"
      end

      if response.status == 200
        parsed = JSON.parse(response.body)
        if parsed.is_a?(Hash) && parsed["anomalies"]
          return parsed["anomalies"]
        elsif parsed.is_a?(Hash) && parsed["data"]
          return parsed["data"]
        else
          return parsed
        end
      else
        Rails.logger.error("[Analytics] Failed to fetch #{path}: ")
        []
      end
    rescue StandardError => e
      Rails.logger.error("[Analytics] Failed to fetch #{path}: #{e.message}")
      []
    end

    def check_permissions
      conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
      res = conn.get("/check_role") do |req|
        req.headers["Authorization"] = "Bearer #{session[:jwt]}"
      end
      if res.status != 200
        flash[:alert] = "You do not have permission to view analytics."
        redirect_to home_path
      end
    end
end
