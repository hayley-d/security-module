# frozen_string_literal: true

class LoginForm
    include ActiveModel::Model
    include ActiveModel::Attributes

    attribute :email,      :string
    attribute :password,   :string

    validates :email,
              presence: { message: "Email is required" },
              format:   { with: /\A[^\s@]+@[^\s@]+\.[^\s@]+\z/, message: "Please enter a valid email" }

    PASSWORD_REGEX = /\A(?=.*[A-Z])(?=.*\d)(?=.*[*,$@!%]).{8,}\z/

    validates :password,
              presence: { message: "Password is required" },
              format:   { with: PASSWORD_REGEX,
                          message: "Min 8 chars, include 1 uppercase, 1 digit, and 1 special (*,$@!%)" }
end
