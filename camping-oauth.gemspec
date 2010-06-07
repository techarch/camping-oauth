require 'rubygems' 

SPEC = Gem::Specification.new do |s| 
  s.name = "camping-oauth" 
  s.version = "1.0.0" 
  s.authors = ["Philippe F. Monnet"]
  s.email = ["pfmonnet@gmail.com"]
  s.homepage = "http://rubyforge.org/projects/camping-oauth/" 
  s.platform = Gem::Platform::RUBY 
  s.summary = "A plugin to add OAuth provider capabilities to a Camping application" 
  s.description = <<-EOF
This is an OAuth plugin for the Ruby Camping framework, inspired by Pelle Braendgaard's OAuth gem and its Rails plugin 
(see http://github.com/pelle/oauth).
The plugin augments a Camping web application with the following routes:
  EOF
  s.rubyforge_project = "camping-oauth"
  candidates = Dir.glob("{bin,doc,lib,test}/**/*") 
  s.files = candidates.delete_if do |item| 
    item.include?("git") || item.include?("rdoc") 
  end 
  s.require_path = "lib" 
  s.autorequire = "camping-oauth" 
  #s.test_file = "test/test_camping-oauth.rb" 
  s.has_rdoc = true 
  s.extra_rdoc_files = ["README"] 
end 
