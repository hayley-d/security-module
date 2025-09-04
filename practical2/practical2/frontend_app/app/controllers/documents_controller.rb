# frozen_string_literal: true

class DocumentsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [ :destroy ]

  def index
    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    access_res = conn.post("/has_access", { permission: "view_doc" }.to_json,
                           "Authorization" => "Bearer #{session[:jwt]}",
                           "Content-Type" => "application/json"
    )
    if access_res.status != 200
      flash[:alert] = "You do not have permission to view documents."
      redirect_to home_path and return
    end
    response = conn.get("/documents/list") do |req|
      req.headers["Authorization"] = "Bearer #{session[:jwt]}"
    end

    if response.status == 200
      @documents = JSON.parse(response.body)
    else
      flash[:alert] = "Failed to load documents"
      @documents = []
    end
  end

  def edit
    asset_id = params[:id]

    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    access_res = conn.post("/has_access", { permission: "update_doc" }.to_json,
                           "Authorization" => "Bearer #{session[:jwt]}",
                           "Content-Type" => "application/json"
    )

    if access_res.status != 200
      flash[:alert] = "You do not have permission to edit this document."
      redirect_to documents_path and return
    end

    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    response = conn.get("/documents/#{asset_id}") do |req|
      req.headers["Authorization"] = "Bearer #{session[:jwt]}"
    end

    if response.status == 200
      @document = JSON.parse(response.body)
      @asset_id = params[:id]
      @mime_type = @document["mimeType"].presence || "application/pdf"
    else
      flash[:alert] = "Failed to load image"
      redirect_to documents_path
    end
  end


  def update
    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    response = conn.patch("/documents/", {
      asset_id: params[:id],
      file_name: params[:file_name],
      description: params[:description],
      updated_by: session[:pending_user],
      mime_type: params[:mime_type],
      asset_type: "document"
    }, { "Authorization" => "Bearer #{session[:jwt]}" })

    if response.status == 200
      flash[:notice] = "Document updated"
      redirect_to documents_path
    else
      flash[:alert] = "Failed to update document"
      redirect_to documents_path
    end
  end

  def download
    asset_id = params[:id]
    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    response = conn.get("/documents/#{asset_id}") do |req|
      req.headers["Authorization"] = "Bearer #{session[:jwt]}"
    end

    if response.status == 200
      data = JSON.parse(response.body)
      byte_array = data["bytes"]["data"]
      file_data = byte_array.pack("C*")

      mime = data["mimeType"]
      mime = "application/#{mime}" unless mime.to_s.start_with?("application/")

      send_data file_data,
                filename: data["file_name"] || "downloaded_document",
                type: mime,
                disposition: "attachment"
    else
      flash[:alert] = "You do not have access to download this document."
      redirect_to documents_path
    end
  end

  def new
    conn = Faraday.new(url: "#{BACKEND_BASE_URL}/roles", ssl: { verify: false })
    access_res = conn.post("/has_access", { permission: "create_doc" }.to_json,
                           "Authorization" => "Bearer #{session[:jwt]}",
                           "Content-Type" => "application/json"
    )

    if access_res.status != 200
      flash[:alert] = "You do not have permission to create documents."
      redirect_to documents_path
    end
  end

  def create
    file = params[:file]
    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    payload = {
      file_name: params[:file_name],
      description: params[:description],
      created_by: session[:pending_user],
      content: file.read.bytes,
      mime_type: normalize_mime_type(file),
      asset_type: "document"
    }
    response = conn.post("/documents/") do |req|
      req.headers["Authorization"] = "Bearer #{session[:jwt]}"
      req.headers["Content-Type"] = "application/json"
      req.body = payload.to_json
    end

    if response.status == 201
      flash[:notice] = "Document created"
      redirect_to documents_path
    else
      flash[:alert] = "Failed to create document"
      render :new, status: :unprocessable_entity
    end
  end

  def destroy
    asset_id = params[:id]

    conn = Faraday.new(url: "#{BACKEND_BASE_URL}", ssl: { verify: false })
    access_res = conn.post("/has_access", { permission: "delete_doc" }.to_json,
                           "Authorization" => "Bearer #{session[:jwt]}",
                           "Content-Type" => "application/json"
    )

    if access_res.status != 200
      flash[:alert] = "You do not have permission to delete documents."
      redirect_to documents_path and return
    end

    response = conn.delete("/documents/#{asset_id}") do |req|
      req.headers["Authorization"] = "Bearer #{session[:jwt]}"
      req.headers["Content-Type"] = "application/json"
    end

    if response.status == 200
      flash[:notice] = "Document deleted successfully"
    else
      flash[:alert] = "Failed to delete document"
    end

    redirect_to documents_path
  end

  private
    def normalize_mime_type(file)
      return nil unless file&.content_type
      file.content_type.split("/").last
    end

end

