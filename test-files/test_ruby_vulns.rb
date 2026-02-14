# Test file for Ruby/Rails security rules
# Contains intentional vulnerabilities for testing

require 'yaml'
require 'open3'

class VulnerableController < ApplicationController
  # SQL Injection - should be detected
  def search
    User.where("name = '#{params[:name]}'")
    User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
    User.order(params[:sort])
    connection.execute("DELETE FROM users WHERE id = #{params[:id]}")
  end

  # Command Injection - should be detected
  def run_command
    system("ls #{params[:dir]}")
    `cat #{params[:file]}`
    exec("ping #{params[:host]}")
    Open3.capture3("grep #{params[:pattern]} file.txt")
  end

  # XSS - should be detected
  def render_html
    raw(params[:content])
    params[:input].html_safe
  end

  # Mass Assignment - should be detected
  def create_user
    params.permit!
    User.create(params[:user])
  end

  # Unsafe Deserialization - should be detected
  def load_config
    YAML.load(params[:config])
    Marshal.load(cookies[:session])
  end

  # Code Injection - should be detected
  def dynamic_code
    eval(params[:code])
    params[:class_name].constantize.new
  end

  # Open Redirect - should be detected
  def redirect_user
    redirect_to params[:url]
  end

  # CSRF Disabled - should be detected
  skip_before_action :verify_authenticity_token

  # SSL Disabled - should be detected
  def fetch_data
    http = Net::HTTP.new(uri.host, uri.port)
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  end

  # Path Traversal - should be detected
  def download
    send_file params[:path]
    File.read(params[:filename])
  end

  # Hardcoded Secrets - should be detected
  SECRET_KEY = "abcdef1234567890abcdef1234567890"
  password = "admin123456"

  # Weak Crypto - should be detected
  def hash_password
    Digest::MD5.hexdigest(password)
    Digest::SHA1.hexdigest(secret)
    OpenSSL::Cipher.new('DES-ECB')
  end

  # Session Secret - should be detected
  config.secret_key_base = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"

  # Render Inline - should be detected
  def unsafe_render
    render inline: params[:template]
  end
end

puts "Test file for Ruby vulnerabilities"
