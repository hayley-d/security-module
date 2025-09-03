# frozen_string_literal: true

class ConfidentialController < ApplicationController

  before_action :check_permissions
  def index
    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    access_res = conn.post("/has_access", { permission: "view_conf" }.to_json,
                           "Authorization" => "Bearer #{session[:jwt]}",
                           "Content-Type" => "application/json"
    )

    if access_res.status != 200
      flash[:alert] = "You do not have permission to read confidential files."
      redirect_to confidential_index_path
    end

    response = conn.get("/confidential/list") do |req|
      req.headers["Authorization"] = "Bearer #{session[:jwt]}"
    end

    if response.status == 200
      @documents = JSON.parse(response.body)
    else
      flash[:alert] = "Failed to load confidential files"
      @documents = []
    end
  end

  def edit
    asset_id = params[:id]

    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    access_res = conn.post("/has_access", { permission: "update_conf" }.to_json,
                           "Authorization" => "Bearer #{session[:jwt]}",
                           "Content-Type" => "application/json"
    )

    if access_res.status != 200
      flash[:alert] = "You do not have permission to edit confidential files."
      redirect_to confidential_index_path and return
    end

    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    response = conn.get("/confidential/#{asset_id}") do |req|
      req.headers["Authorization"] = "Bearer #{session[:jwt]}"
    end

    if response.status == 200
      @document = JSON.parse(response.body)
      @asset_id = params[:id]
    else
      flash[:alert] = "Failed to load confidential file"
      redirect_to confidential_index_path
    end
  end


  def update
    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    response = conn.patch("/confidential/", {
      asset_id: params[:id],
      file_name: params[:file_name],
      description: params[:description],
      content: params[:content],
      updated_by: session[:pending_user],
      mime_type: "application/text",
      asset_type: "confidential"
    }, { "Authorization" => "Bearer #{session[:jwt]}" })

    if response.status == 200
      flash[:notice] = "Confidential file updated"
      redirect_to confidential_index_path
    else
      flash[:alert] = "Failed to update confidential file."
      redirect_to confidential_index_path
    end
  end

  def download
    asset_id = params[:id]
    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    access_res = conn.post("/has_access", { permission: "view_conf" }.to_json,
                           "Authorization" => "Bearer #{session[:jwt]}",
                           "Content-Type" => "application/json"
    )

    if access_res.status != 200
      flash[:alert] = "You do not have permission to read confidential files."
      redirect_to confidential_index_path
    end

    response = conn.get("/confidential/#{asset_id}") do |req|
      req.headers["Authorization"] = "Bearer #{session[:jwt]}"
    end

    if response.status == 200
      data = JSON.parse(response.body)

      file_data = data["content"]

      mime = data["mimeType"]
      mime = "application/#{mime}" unless mime.to_s.start_with?("application/")

      send_data file_data,
                filename: data["file_name"] || "downloaded_confidential_file",
                type: mime,
                disposition: "attachment"
    else
      flash[:alert] = "You do not have access to download this file."
      redirect_to confidential_index_path
    end
  end

  def new
    conn = Faraday.new(url: "#{BACKEND_BASE_URL}/roles", ssl: { verify: false })
    access_res = conn.post("/has_access", { permission: "create_conf" }.to_json,
                           "Authorization" => "Bearer #{session[:jwt]}",
                           "Content-Type" => "application/json"
    )

    if access_res.status != 200
      flash[:alert] = "You do not have permission to create confidential files."
      redirect_to confidential_index_path
    end
  end

  def create
    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    payload = {
      file_name: params[:file_name],
      description: params[:description],
      created_by: session[:pending_user],
      content: params[:content],
      mime_type: "application/text",
      asset_type: "confidential"
    }
    response = conn.post("/confidential/") do |req|
      req.headers["Authorization"] = "Bearer #{session[:jwt]}"
      req.headers["Content-Type"] = "application/json"
      req.body = payload.to_json
    end

    if response.status == 201
      flash[:notice] = "New confidential file created"
      redirect_to confidential_index_path
    else
      flash[:alert] = "Failed to create document"
      render :new, status: :unprocessable_entity
    end
  end

  def destroy
    asset_id = params[:id]

    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    access_res = conn.post("/has_access", { permission: "delete_conf" }.to_json,
                           "Authorization" => "Bearer #{session[:jwt]}",
                           "Content-Type" => "application/json"
    )

    if access_res.status != 200
      flash[:alert] = "You do not have permission to delete confidential files."
      redirect_to confidential_index_path and return
    end

    response = conn.delete("/confidential/#{asset_id}") do |req|
      req.headers["Authorization"] = "Bearer #{session[:jwt]}"
      req.headers["Content-Type"] = "application/json"
    end

    if response.status == 200
      flash[:notice] = "Confidential file deleted successfully"
    else
      flash[:alert] = "Failed to delete confidential file"
    end

    redirect_to confidential_index_path
  end


  private
    def normalize_mime_type(file)
      return nil unless file&.content_type
      file.content_type.split("/").last
    end

    def check_permissions
      conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
      access_res = conn.post("/has_access", { permission: "view_conf" }.to_json,
                             "Authorization" => "Bearer #{session[:jwt]}",
                             "Content-Type" => "application/json"
      )

      if access_res.status != 200
        flash[:alert] = "You do not have permission to view confidential files."
        redirect_to home_path
      end
    end

end

