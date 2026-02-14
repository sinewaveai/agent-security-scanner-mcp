#!/usr/bin/perl
# Test file for hallucination detection
# Contains mix of real and fake Perl packages

use strict;
use warnings;

# Real packages (verified to exist in dataset)
use DBI::Filesystem;
use DBI::Transaction;
use XML::Fast;
use DateTime::Astro;
use DateTime::Format::Builder;

# Hallucinated packages (should be detected as fake)
use AI::MagicHelper::Pro;
use Super::FastParser::Ultra;
use Ultra::WebFramework::Magic;
use Awesome::DataProcessor::Fake;
use Magic::StringUtils::NotReal;

print "Testing hallucination detection\n";
