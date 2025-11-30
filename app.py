import os
import uuid
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

import boto3
import requests
from flask import Flask, request, render_template, jsonify, url_for, redirect
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError
from jose.utils import base64url_decode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from botocore.exceptions import ClientError
from plant_disease_lib import PlantDiseasePredictor

COGNITO_REGION = os.getenv('COGNITO_REGION')
COGNITO_APP_CLIENT_ID = os.getenv('COGNITO_APP_CLIENT_ID')
USERPOOL_ID = os.getenv('COGNITO_USERPOOL_ID')
BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
DDB_TABLE_NAME = os.getenv('DDB_TABLE_NAME')
SNS_TOPIC_ARN = os.getenv('AWS_SNS_TOPIC_ARN')

JWKS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{USERPOOL_ID}/.well-known/jwks.json"

sns_client = boto3.client('sns', region_name=COGNITO_REGION)


predictor = PlantDiseasePredictor(
    model_path="models/plant_disease_model_1_latest.pt",
    disease_csv_path="disease_info.csv",
    supplement_csv_path="supplement_info.csv",
)

app = Flask(__name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
_jwks_cache = None

@app.template_filter('s3_url')
def s3_url_filter(key):
    s3_client = boto3.client('s3', region_name=COGNITO_REGION)
    try:
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET_NAME, 'Key': key},
            ExpiresIn=3600
        )
        return url
    except Exception:
        return '#'

@app.template_filter('format_timestamp')
def format_timestamp(ts):
    try:
        dt = datetime.fromtimestamp(int(ts))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_jwks():
    global _jwks_cache
    if not _jwks_cache:
        resp = requests.get(JWKS_URL)
        resp.raise_for_status()
        _jwks_cache = resp.json()
    return _jwks_cache

def construct_rsa_key(key_dict):
    n_str, e_str = key_dict['n'], key_dict['e']
    n_bytes = n_str.encode('utf-8') if isinstance(n_str, str) else n_str
    e_bytes = e_str.encode('utf-8') if isinstance(e_str, str) else e_str
    n_int = int.from_bytes(base64url_decode(n_bytes), 'big')
    e_int = int.from_bytes(base64url_decode(e_bytes), 'big')
    public_numbers = rsa.RSAPublicNumbers(e_int, n_int)
    public_key = public_numbers.public_key(default_backend())
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def verify_token(token):
    jwks = get_jwks()
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')
        key = next((k for k in jwks['keys'] if k['kid'] == kid), None)
        if not key:
            raise ValueError("Public key not found in JWKS")
        public_key_pem = construct_rsa_key(key)
        payload = jwt.decode(
            token,
            public_key_pem,
            algorithms=['RS256'],
            audience=COGNITO_APP_CLIENT_ID,
            issuer=f'https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{USERPOOL_ID}'
        )
        return payload
    except ExpiredSignatureError:
        raise ValueError("Token expired")
    except JWTError as e:
        raise ValueError(f"Invalid token: {str(e)}")

def get_s3_client():
    return boto3.client('s3', region_name=COGNITO_REGION)

def get_table():
    dynamodb = boto3.resource('dynamodb', region_name=COGNITO_REGION)
    return dynamodb.Table(DDB_TABLE_NAME)

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/auth')
def auth():
    return render_template('auth.html')

@app.route('/detect')
def detect():
    return render_template('detect.html')

@app.route('/result')
def result():
    image_id = request.args.get('image_id', None)
    if not image_id:
        return "ImageId not provided!", 400
    table = get_table()
    s3_client = get_s3_client()
    try:
        response = table.get_item(Key={'ImageId': image_id})
        item = response.get('Item', None)
        if not item:
            return "Result not found!", 404
    except Exception as e:
        error_message = str(e)
        if "UnrecognizedClientException" in error_message or "security token" in error_message:
            return "AWS credentials have expired or are invalid.", 500
        return f"Error reading record: {error_message}", 500  
    presigned_url = s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': BUCKET_NAME, 'Key': item['S3Key']},
        ExpiresIn=3600
    )
    try:
        prediction_index = int(item.get('Prediction', 0)) if item.get('Prediction') else 0
    except Exception:
        prediction_index = 0
    disease_metadata = predictor.predict_with_metadata_by_index(prediction_index)

    title = disease_metadata.get("disease_title", "Unknown")
    background_no_leaf = (title.strip().lower() == "background without leaves")
    sample_leaf_image_url = "/static/assets/sample_leaf.jpg"

    raw_prevent_text = disease_metadata.get("prevent", "")
    prevention_steps = [s.strip() for s in raw_prevent_text.split('. ') if s.strip()]
    prevention_steps = [s if s.endswith('.') else s + '.' for s in prevention_steps]

    disease_data = {
        "name": title,
        "description": disease_metadata.get("description", "No description found."),
        "preventionSteps": prevention_steps,
        "supplements": [{
            "name": disease_metadata.get("supplement_name", ""),
            "image": disease_metadata.get("supplement_image_url", ""),
            "link": disease_metadata.get("supplement_buy_link", ""),
        }],
        "background_no_leaf": background_no_leaf,
        "sample_leaf_image": sample_leaf_image_url
    }
    return render_template('results.html', disease_data=disease_data, image_url=presigned_url)

# Result polling
@app.route('/result_api')
def result_api():
    image_id = request.args.get('image_id')
    table = get_table()
    try:
        response = table.get_item(Key={'ImageId': image_id})
        item = response.get('Item', None)
        return jsonify({'found': item is not None})
    except Exception as e:
        return jsonify({'found': False, 'error': str(e)})

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    cognito_client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
    try:
        cognito_client.sign_up(
            ClientId=COGNITO_APP_CLIENT_ID,
            Username=data['username'],
            Password=data['password'],
            UserAttributes=[
                {'Name': 'email', 'Value': data['email']},
                {'Name': 'given_name', 'Value': data['given_name']}
            ]
        )
        return jsonify(success=True)
    except ClientError as e:
        return jsonify(success=False, message=e.response['Error']['Message'])

@app.route('/api/confirm-signup', methods=['POST'])
def confirm_signup():
    data = request.json
    cognito_client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
    try:
        cognito_client.confirm_sign_up(
            ClientId=COGNITO_APP_CLIENT_ID,
            Username=data['username'],
            ConfirmationCode=data['confirmation_code']
        )
        return jsonify(success=True)
    except ClientError as e:
        return jsonify(success=False, message=e.response['Error']['Message'])

@app.route('/api/signin', methods=['POST'])
def signin():
    data = request.json
    cognito_client = boto3.client('cognito-idp', region_name=COGNITO_REGION)
    try:
        response = cognito_client.initiate_auth(
            ClientId=COGNITO_APP_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': data['username'],
                'PASSWORD': data['password']
            }
        )
        tokens = response.get('AuthenticationResult', {})
        return jsonify(success=True, tokens=tokens)
    except ClientError as e:
        return jsonify(success=False, message=e.response['Error']['Message'])

@app.route('/api/upload', methods=['POST'])
def upload_file():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify(success=False, message='Missing or invalid authorization token'), 401
    token = auth_header[7:]
    try:
        token_payload = verify_token(token)
    except ValueError as e:
        return jsonify(success=False, message=f'Invalid token: {str(e)}'), 401
    if 'file' not in request.files:
        return jsonify(success=False, message='No file part in request'), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify(success=False, message='No selected file'), 400
    if file and allowed_file(file.filename):
        extension = os.path.splitext(file.filename)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}{extension}"
        s3_key = f"images/{unique_filename}"
        temp_path = f"/tmp/{unique_filename}"
        s3_client = get_s3_client()
        try:
            file_content = file.read()
            username = token_payload.get('username') or token_payload.get('email', 'unknown')
            with open(temp_path, "wb") as temp_file:
                temp_file.write(file_content)
            prediction_index = predictor.predict_index(temp_path)
            prediction_str = str(prediction_index)
            s3_client.upload_file(
                temp_path,
                BUCKET_NAME,
                s3_key,
                ExtraArgs={
                    "ContentType": file.content_type,
                    "Metadata": {
                        "uploadedby": username,
                        "prediction": prediction_str,
                    },
                },
            )
            redirect_url = url_for('result', image_id=unique_filename)
            return jsonify(success=True, redirect=redirect_url, user=username, prediction=prediction_index)
        except Exception as e:
            return jsonify(success=False, message=f"Upload and prediction failed: {str(e)}"), 500
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
    else:
        return jsonify(success=False, message='Invalid file type'), 400

@app.route('/history')
def history():
    username = request.args.get('username')
    if not username:
        return redirect(url_for('auth'))

    page = int(request.args.get('page', 1))
    per_page = 10
    start = (page - 1) * per_page
    end = start + per_page

    try:
        response = get_table().scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('UploadedBy').eq(username)
        )
        all_items = response.get('Items', [])

        # Enrich each item with prediction metadata and formatted timestamp
        for item in all_items:
            try:
                prediction_index = int(item.get('Prediction', 0)) if item.get('Prediction') else 0
            except Exception:
                prediction_index = 0

            metadata = predictor.predict_with_metadata_by_index(prediction_index)
            item['prediction_title'] = metadata.get('disease_title', 'Unknown')
            item['prediction_description'] = metadata.get('description', 'No description available')

            ts = item.get('Timestamp')
            if ts:
                dt = datetime.fromtimestamp(int(ts))
                item['timestamp'] = dt.strftime('%Y-%m-%d %H:%M:%S')
            else:
                item['timestamp'] = ''

        all_items.sort(key=lambda x: int(x.get('Timestamp', 0)), reverse=True)
        page_items = all_items[start:end]
        total_pages = (len(all_items) + per_page - 1) // per_page

    except ClientError as e:
        page_items = []
        total_pages = 0

    return render_template(
        'history.html',
        records=page_items,
        page=page,
        total_pages=total_pages,
        username=username
    )

@app.route('/history/edit/<string:image_id>', methods=['POST'])
def edit_history(image_id):
    is_resolved_str = request.form.get('is_resolved')
    if is_resolved_str is None:
        return jsonify(success=False, message="Missing resolved status")

    is_resolved = is_resolved_str.lower() in ('true', '1', 'yes', 'on')

    try:
        get_table().update_item(
            Key={'ImageId': image_id},
            UpdateExpression="set is_resolved = :ir",
            ExpressionAttributeValues={':ir': is_resolved}
        )
        return jsonify(success=True, message="Resolved status updated successfully")
    except ClientError as e:
        return jsonify(success=False, message=f"Update failed: {e.response['Error']['Message']}")

        
from flask import request, jsonify

from flask import request, jsonify

@app.route('/send_help', methods=['POST'])
def send_help():
    print(request.form)
    image_id = request.form.get('image_id', None)
    disease_name = request.form.get('disease_name', 'Unknown disease')
    username = request.form.get('username', 'Unknown user')
    email = request.form.get('email', 'Unknown email')

    if not image_id:
        return jsonify(success=False, message="Missing image_id"), 400

    # Compose the SNS message
    message = (
        f"User '{username}' with email '{email}' requests help for:\n"
        f"Disease: {disease_name}\n"
        f"Image ID: {image_id}"
    )

    try:
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=f"Help Request from {username}"
        )
        return jsonify(success=True, message="Help request sent successfully")
    except Exception as e:
        return jsonify(success=False, message=f"Failed to send help request: {str(e)}"), 500


@app.route('/history/delete/<string:image_id>', methods=['POST'])
def delete_history(image_id):
    try:
        get_table().delete_item(Key={'ImageId': image_id})
        return jsonify(success=True, message="Record deleted successfully")
    except ClientError as e:
        return jsonify(success=False, message=f"Delete failed: {e.response['Error']['Message']}")
        


if __name__ == '__main__': 
    app.run(debug=True, port=8080)