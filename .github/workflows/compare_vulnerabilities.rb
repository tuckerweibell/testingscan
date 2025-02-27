require 'json'
require 'fileutils'
require 'set'

# Load the vulnerabilities from the JSON files
def load_vulnerabilities(file)
  JSON.parse(File.read(file))
end

# Parse the vulnerabilities and return an array of hashes with required attributes
def parse_vulnerabilities(vulnerabilities_json)
  vulnerabilities_json['Results'].flat_map do |result|
    result['Vulnerabilities'].map do |vuln|
      {
        vulnerability_id: vuln['VulnerabilityID'],
        package_uid: vuln['PkgIdentifier']['UID'],
        target_file: result['Target'],
        severity: vuln['Severity'],
        title: vuln['Title'],
        fixed_version: vuln['FixedVersion'],
        pkg_name: vuln['PkgName'],
        installed_version: vuln['InstalledVersion'],
        cvss_score: vuln['CVSSScore'],
        published_date: vuln['PublishedDate'],
        description: vuln['Description'],
        references: vuln['References'] || []
      }
    end
  end
end

# Compare vulnerabilities and return a list of new ones based on VulnerabilityID, PackageUID, and TargetFile
def compare_vulnerabilities(base_vulnerabilities, head_vulnerabilities)
  # Create sets of vulnerability data from base and head
  base_set = base_vulnerabilities.map { |vuln| [vuln[:vulnerability_id], vuln[:package_uid], vuln[:target_file]] }.to_set
  head_set = head_vulnerabilities.map { |vuln| [vuln[:vulnerability_id], vuln[:package_uid], vuln[:target_file]] }.to_set

  # Find vulnerabilities in the head that are not in the base (i.e., newly introduced)
  new_vulnerabilities = head_set - base_set

  # Map back to original vuln details for the new vulnerabilities
  new_vulnerabilities_details = new_vulnerabilities.map do |vuln|
    head_vulnerabilities.find { |h| h[:vulnerability_id] == vuln[0] && h[:package_uid] == vuln[1] && h[:target_file] == vuln[2] }
  end

  new_vulnerabilities_details
end

# Write the new vulnerabilities to a file or output
def output_new_vulnerabilities(new_vulnerabilities)
  if new_vulnerabilities.empty?
    puts "No new vulnerabilities introduced."
  else
    puts "New vulnerabilities introduced:"
    new_vulnerabilities.each do |vuln|
      puts "----------------------------------------"
      puts "Vulnerability ID: #{vuln[:vulnerability_id]} (Severity: #{vuln[:severity]})"
      puts "  File: #{vuln[:target_file]}"
      puts "  Package: #{vuln[:pkg_name]} (Installed Version: #{vuln[:installed_version]})"
      puts "  Fixed Version: #{vuln[:fixed_version]}"
      puts "  CVSS Score: #{vuln[:cvss_score]}"
      puts "  Published Date: #{vuln[:published_date]}"
      puts "  Description: #{vuln[:description]}"
      puts "  References:"
      vuln[:references].each do |ref|
        puts "    - #{ref}"
      end
      puts "----------------------------------------"
    end
    exit(1)  # Fail the build if new vulnerabilities are introduced
  end
end

# Main comparison logic
def run_comparison(base_file, head_file)
  # Load and parse JSON files
  base_vulnerabilities = load_vulnerabilities(base_file)
  head_vulnerabilities = load_vulnerabilities(head_file)

  base_parsed = parse_vulnerabilities(base_vulnerabilities)
  head_parsed = parse_vulnerabilities(head_vulnerabilities)

  # Compare vulnerabilities and identify new ones
  new_vulnerabilities = compare_vulnerabilities(base_parsed, head_parsed)

  # Output results
  output_new_vulnerabilities(new_vulnerabilities)
end

# Run the comparison with the paths to the base and head commit JSON files
base_file = 'base_vulnerabilities.json'
head_file = 'head_vulnerabilities.json'

run_comparison(base_file, head_file)
