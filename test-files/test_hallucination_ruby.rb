# Test file for Ruby/RubyGems package hallucination detection
# Mix of real and fake packages

# Real gems (should be found in RubyGems)
require 'rails'
require 'sinatra'
require 'nokogiri'
require 'rspec'
require 'puma'

# Fake/hallucinated gems (should be detected)
require 'super_ai_helper_magic'
require 'ultra_data_processor_fake'
require 'awesome_ml_utils_notreal'
require 'magic_http_client_xyz'
require 'flutter_ruby_bridge_fake'

gem 'sidekiq'  # Real
gem 'fake_sidekiq_pro_ultra'  # Fake
