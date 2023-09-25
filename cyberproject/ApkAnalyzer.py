import os
from flask import Flask, render_template, request, send_from_directory, make_response
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from androguard.core.bytecodes import apk
import json
from flask import Response
import subprocess
import requests

app = Flask(__name__)

# Specify the absolute path to the uploads directory
uploads_dir = os.path.join(os.path.dirname(__file__), 'uploads')

# Check if the directory exists; if not, create it
if not os.path.exists(uploads_dir):
    os.makedirs(uploads_dir)

# Load descriptions from a JSON file
descriptions_file = 'descriptions.json'
with open(descriptions_file, 'r', encoding='utf-8') as f:
    descriptions = json.load(f)

# Function to run MobSF for security analysis

mobsf_api_key = 'fe1ecdb0d47ddca6f3890271390b8c27eededb688d72f4440602978c63721f28'

def run_mobsf(apk_path):
    try:
        # Send a POST request to MobSF for analysis
        url = 'http://127.0.0.1:8000/api/v1/upload'
        files = {'file': open(apk_path, 'rb')}
        headers = {'Authorization': f'Token {mobsf_api_key}'}
        response = requests.post(url, files=files, headers=headers)
        
        # Check if the analysis was successful
        if response.status_code == 200:
            analysis_result = response.text
        else:
            analysis_result = f"Security analysis failed. MobSF returned status code {response.status_code}"
        
        return analysis_result
    except Exception as e:
        return f"Security analysis failed. Error: {str(e)}"

@app.route('/')
def index():
    return render_template('ApkAnalyzer.html')

@app.route('/upload', methods=['POST'])
def upload_apk():
    if 'apkFile' not in request.files:
        return "No APK file provided."

    apk_file = request.files['apkFile']

    if apk_file.filename == '':
        return "No selected file."

    # Specify the destination file path
    dst = os.path.join(uploads_dir, apk_file.filename)

    # Open and write the file
    with open(dst, "wb") as file:
        file.write(apk_file.read())

    a = apk.APK(dst)

    # Extract package name, version code, and version name
    package_name = a.get_package()
    version_code = a.get_androidversion_code()
    version_name = a.get_androidversion_name()

    # Extract permissions
    permissions = a.get_permissions()

    # Extract activities, services, receivers, and providers
    activities = a.get_activities()
    services = a.get_services()
    receivers = a.get_receivers()
    providers = a.get_providers()

    # Extract descriptions from the manifest file
    manifest_descriptions = []
    try:
        manifest = a.get_android_manifest_xml()
        for element in manifest.getElementsByTagName('activity'):
            name = element.getAttribute('android:name')
            description = element.getAttribute('android:label')
            manifest_descriptions.append((name, description))
    except Exception as e:
        print(f"Error extracting descriptions from manifest: {str(e)}")

    # Extract the app description from the manifest
    app_description = ""
    try:
        app_description = manifest.getElementsByTagName('application')[0].getAttribute('android:description')
    except Exception as e:
        print(f"Error extracting app description: {str(e)}")

    # Generate a PDF report using ReportLab
    pdf_report_path = os.path.join(uploads_dir, 'analysis_report.pdf')
    doc = SimpleDocTemplate(pdf_report_path, pagesize=letter)

    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph("APK Analysis Report", styles['Title']))

    # Include the package name, version code, and version name
    package_info = f"Package Name: {package_name}<br/>Version Code: {version_code}<br/>Version Name: {version_name}"
    story.append(Paragraph(package_info, styles['Normal']))

    # Include the app description
    story.append(Paragraph("App Description:", styles['Heading2']))
    story.append(Paragraph(app_description, styles['Normal']))

    # Include detailed information
    story.append(Paragraph("Permissions:", styles['Heading2']))
    for permission in permissions:
        description = descriptions.get(permission, "No description available")
        story.append(Paragraph(f"<strong>{permission}</strong>: {description}", styles['Normal']))

    story.append(Paragraph("Activities:", styles['Heading2']))
    for activity in activities:
        description = descriptions.get(activity, "No description available")
        story.append(Paragraph(f"<strong>{activity}</strong>: {description}", styles['Normal']))

    # Include descriptions extracted from manifest
    story.append(Paragraph("Descriptions from Manifest:", styles['Heading2']))
    for name, description in manifest_descriptions:
        story.append(Paragraph(f"<strong>{name}</strong>: {description}", styles['Normal']))

    # Extract broadcast receivers and content providers
    broadcast_receivers = a.get_receivers()
    broadcast_receivers_info = {}
    for receiver in broadcast_receivers:
        receiver_description = descriptions.get(receiver, "No description available")
        broadcast_receivers_info[receiver] = receiver_description

    content_providers = a.get_providers()
    content_providers_info = {}
    for provider in content_providers:
        provider_description = descriptions.get(provider, "No description available")
        content_providers_info[provider] = provider_description

    # Include broadcast receivers in the report
    story.append(Paragraph("App Broadcast Receivers:", styles['Heading2']))
    for receiver, description in broadcast_receivers_info.items():
        story.append(Paragraph(f"<strong>{receiver}</strong>: {description}", styles['Normal']))

    # Include content providers in the report
    story.append(Paragraph("App Content Providers:", styles['Heading2']))
    for provider, description in content_providers_info.items():
        story.append(Paragraph(f"<strong>{provider}</strong>: {description}", styles['Normal']))

    # Security Analysis
    security_analysis = run_mobsf(dst)
    story.append(Paragraph("Security Analysis:", styles['Heading2']))
    story.append(Paragraph(security_analysis, styles['Normal']))

    # Build the PDF report
    doc.build(story)

    # Serve the PDF as a response
    with open(pdf_report_path, 'rb') as pdf_file:
        pdf_data = pdf_file.read()

    response = Response(pdf_data, content_type='application/pdf')
    response.headers['Content-Disposition'] = f'inline; filename=analysis_report.pdf'

    return response

@app.route('/download')
def download_pdf():
    pdf_report_path = os.path.join(uploads_dir, 'analysis_report.pdf')
    return send_from_directory(uploads_dir, 'analysis_report.pdf')

if __name__ == '__main__':
    app.run(debug=True)
