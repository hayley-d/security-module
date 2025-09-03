# frozen_string_literal: true

class SessionsController < ApplicationController



  def new
    @form = LoginForm.new
  end

  def login
    @form = LoginForm.new(login_params)

    unless @form.valid?
      flash.now[:alert] = "Please fix the errors below"
      return render :new_register, status: :unprocessable_entity
    end

    conn = Faraday.new(url: BACKEND_BASE_URL, ssl: { verify: false })
    response = conn.post("#{BACKEND_BASE_URL}/login", {
      user_email: login_params[:email],
      password: login_params[:password]
    })

    body = JSON.parse(response.body)

    if body["mfa_required"]
      session[:pending_user] = body["user_id"]
      session[:pending_user_email] = body["user_email"]
      redirect_to otp_path
    else
      flash[:alert] = "Invalid login credentials"
      render :new, status: :unprocessable_entity
    end
  end

  def otp
    # Renders OTP form
  end

  def verify_otp
    conn = Faraday.new(url: BACKEND_BASE_URL, ssl: { verify: false })
    response = conn.post("#{BACKEND_BASE_URL}/verify", {
      user_email: session[:pending_user_email],
      current_ip: request.remote_ip,
      otp: params[:otp]
    })

    body = JSON.parse(response.body)

    if body["ok"]
      session[:jwt] = body["token"]
      flash[:notice] = "Logged in successfully"
      redirect_to home_path
    else
      flash[:alert] = "Invalid OTP"
      render :otp, status: :unprocessable_entity
    end
  end

  def new_register
    @form = RegisterForm.new
  end

  def create_register
    @form = RegisterForm.new(register_params)

    unless @form.valid?
      flash.now[:alert] = "Please fix the errors below"
      return render :new_register, status: :unprocessable_entity
    end

    conn = Faraday.new(url: BACKEND_BASE_URL, ssl: { verify: false })
    response = conn.post("#{BACKEND_BASE_URL}/register", {
      first_name: register_params[:first_name],
      last_name: register_params[:last_name],
      email: register_params[:email],
      password: register_params[:password]
    })

    body = JSON.parse(response.body)

    if body["user_email"] && body["url"]
      session[:pending_email] = body["user_email"]
      session[:mfa_url] = body["url"]
      redirect_to setup_mfa_path
    else
      flash[:alert] = "Registration failed"
      render :new_register, status: :unprocessable_entity
    end
  end

  def setup_mfa
    @mfa_url = session[:mfa_url]
  end

  def verify_mfa
    conn = Faraday.new(url: BACKEND_BASE_URL, ssl: { verify: false })
    response = conn.post("#{BACKEND_BASE_URL}/two_factor", {
      user_email: session[:pending_email],
      token: params[:otp]
    })

    if response.status == 200
      body = JSON.parse(response.body)
      session[:jwt] = body["token"]
      flash[:notice] = "Welcome! Your account is now verified."
      redirect_to login_path
    else
      flash[:alert] = "Invalid OTP"
      redirect_to otp_path
    end
  end

  def destroy
    reset_session
    redirect_to login_path
  end

  private
    def register_params
      params.require(:register_form)
            .permit(:first_name, :last_name, :email, :password)
    end

    def login_params
      params.permit(:email, :password)
    end
end
