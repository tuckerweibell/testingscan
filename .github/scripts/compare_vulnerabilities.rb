name: Dependency Vulnerability Check

on:
  pull_request:
    paths:
      - '**/Gemfile.lock'
      - '**/package-lock.json'
      - '**/yarn.lock'
      - '**/pnpm-lock.yaml'

jobs:
  vulnerability-check:
    runs-on: ubuntu-latest
    container:
      image: ruby:3.1 # Specify the Ruby Docker image and version (you can use any Ruby version)

    steps:
    - name: Checkout the code
      uses: actions/checkout@v3
      with:
        fetch-depth: 0

    - name: Install Bundler
      run: gem install bundler

    - name: Run Trivy on base commit
      id: trivy-base
      run: |
        git checkout origin/main
        trivy fs --quiet --scanners vuln --pkg-types library -s HIGH,CRITICAL --format json . > base_vulnerabilities.json

    - name: Run Trivy on head commit
      id: trivy-head
      run: |
        git checkout FETCH_HEAD
        trivy fs --quiet --scanners vuln --pkg-types library -s HIGH,CRITICAL --format json . > head_vulnerabilities.json

    - name: Run Ruby script to compare vulnerabilities
      id: compare-vulnerabilities
      run: |
        ruby .github/scripts/compare_vulnerabilities.rb
    
    - name: Generate comment content with CVE IDs and Descriptions
      id: generate-comment
      run: |
        NEW_VULNS=$(ruby .github/scripts/compare_vulnerabilities.rb | grep "CVE-" | awk '{print "- **" $1 "**\n  - " $2}')
        echo "NEW_VULNS=${NEW_VULNS}" >> $GITHUB_ENV

    - name: Post comment to GitHub PR with vulnerability summary
      uses: actions/github-script@v7
      with:
        github-token: ${{ secrets.GITHUB_TOKEN }}
        script: |
          const newVulns = process.env.NEW_VULNS;
          const commentBody = `
          ### New Vulnerabilities Introduced 🚨
          ${newVulns}
          
          Please check the full GitHub Actions log for more details.`;

          await github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: commentBody
          });
