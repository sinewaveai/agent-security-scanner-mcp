#!/usr/bin/env raku
# Test file for hallucination detection
# Contains mix of real and fake Raku packages

# Real packages (should be legitimate)
use JSON::Fast;
use HTTP::UserAgent;
use DBIish;
use XML;
use Cro::HTTP::Client;

# Hallucinated packages (should be detected as fake)
use AI::SuperHelper;
use Magic::DataParser;
use Ultra::WebServer;
use Awesome::StringTools;
use Fantasy::Module;

say "Testing hallucination detection";
