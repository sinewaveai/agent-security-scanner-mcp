# Benchmark corpus: Ruby security vulnerabilities

# --- SQL Injection (Rails) ---

# VULN: sql-injection-where
User.where("name = '#{params[:name]}'")

# VULN: sql-injection-order
User.order("#{params[:column]} DESC")

# VULN: sql-injection-raw
ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = #{params[:id]}")

# SAFE: sql-injection-where
User.where(name: params[:name])

# SAFE: sql-injection-where
User.where("name = ?", params[:name])

# --- Command Injection ---

# VULN: command-injection-system
system("cat " + params[:file])

# VULN: command-injection-system
`ls #{user_input}`

# VULN: command-injection-open
IO.popen("grep #{pattern}")

# SAFE: command-injection-system
system("cat", params[:file])

# SAFE: command-injection-open
IO.popen(["grep", pattern])

# --- XSS (Rails) ---

# VULN: xss-raw
raw(params[:content])

# VULN: xss-content-tag
content_tag(:div, params[:data].html_safe)

# SAFE: xss-raw
ERB::Util.html_escape(params[:content])

# SAFE: xss-content-tag
content_tag(:div, params[:data])

# --- Mass Assignment ---

# VULN: mass-assignment-permit-all
params.require(:user).permit!

# SAFE: mass-assignment-permit-all
params.require(:user).permit(:name, :email)

# --- Unsafe Find ---

# VULN: unscoped-find
User.unscoped.find(params[:id])

# SAFE: unscoped-find
User.find(params[:id])

# --- Deserialization ---

# VULN: unsafe-yaml-load
YAML.load(user_input)

# VULN: unsafe-marshal
Marshal.load(user_data)

# SAFE: unsafe-yaml-load
YAML.safe_load(user_input)

# SAFE: unsafe-marshal
JSON.parse(user_data)

# --- Code Injection ---

# VULN: eval-usage
eval(params[:code])

# VULN: constantize
params[:class].constantize

# SAFE: eval-usage
result = JSON.parse(params[:data])

# --- Open Redirect ---

# VULN: open-redirect
redirect_to params[:url]

# SAFE: open-redirect
redirect_to root_path

# --- CSRF ---

# VULN: csrf-disabled
skip_before_action :verify_authenticity_token

# SAFE: csrf-disabled
protect_from_forgery with: :exception

# --- SSL/TLS ---

# VULN: ssl-verify-disabled
Net::HTTP.start(uri.host, uri.port, verify_mode: OpenSSL::SSL::VERIFY_NONE)

# SAFE: ssl-verify-disabled
Net::HTTP.start(uri.host, uri.port, verify_mode: OpenSSL::SSL::VERIFY_PEER)

# --- Path Traversal ---

# VULN: path-traversal
File.read("/uploads/" + params[:file])

# VULN: path-traversal
File.open("../../../etc/passwd")

# SAFE: path-traversal
File.read(File.join("/uploads", File.basename(params[:file])))

# --- Hardcoded Secrets ---

# VULN: hardcoded-secret
api_key = "sk_live_12345abcdef"

# VULN: session-secret-hardcoded
Rails.application.config.secret_key_base = "hardcoded_secret_key_12345"

# SAFE: hardcoded-secret
api_key = ENV['API_KEY']

# --- Weak Cryptography ---

# VULN: weak-hash
Digest::MD5.hexdigest(password)

# VULN: weak-cipher
cipher = OpenSSL::Cipher.new('DES')

# SAFE: weak-hash
BCrypt::Password.create(password)

# --- ReDoS ---

# VULN: regex-dos
/^(a+)+$/.match(user_input)

# SAFE: regex-dos
/^a+$/.match(user_input)

# --- Render Inline ---

# VULN: render-inline
render inline: params[:template]

# SAFE: render-inline
render template: "users/show"
