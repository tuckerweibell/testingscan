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
    # Ensure that 'Vulnerabilities' exists and is not nil
    next if result['Vulnerabilities'].nil?

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
  end.compact # Remove nil entries from the result
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

# Generate a markdown string with the CVE IDs and Descriptions for the PR comment
def generate_cve_markdown(new_vulnerabilities)
  if new_vulnerabilities.empty?
    return "No new vulnerabilities introduced. 🎉"
  else
    markdown = "### New Vulnerabilities Introduced 🚨\n\n"
    new_vulnerabilities.each do |vuln|
      markdown += "- **CVE ID:** #{vuln[:vulnerability_id]}\n  - **Description:** #{vuln[:description]}\n\n"
    end
    markdown += "Please check the full GitHub Actions log for more details."
    markdown
  end
end

# Write the markdown content to a file for GitHub Actions to read
def write_markdown_to_file(markdown)
  File.open('vulnerability_comment.md', 'w') do |file|
    file.puts(markdown)
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

  # Generate the markdown summary for the GitHub comment
  markdown = generate_cve_markdown(new_vulnerabilities)

  # Write the markdown to a file for GitHub Actions to read
  write_markdown_to_file(markdown)
end

# Run the comparison with the paths to the base and head commit JSON files
base_file = 'base_vulnerabilities.json'
head_file = 'head_vulnerabilities.json'

run_comparison(base_file, head_file)
