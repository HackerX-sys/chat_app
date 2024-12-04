import os
from werkzeug.utils import secure_filename
from datetime import datetime
from flask import current_app
import magic
import uuid

ALLOWED_EXTENSIONS = {
    'image': {'png', 'jpg', 'jpeg', 'gif'},
    'document': {'pdf', 'doc', 'docx', 'txt'},
    'audio': {'mp3', 'wav'},
    'video': {'mp4', 'avi', 'mov'}
}

def allowed_file(filename, file_type=None):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    if file_type:
        return ext in ALLOWED_EXTENSIONS.get(file_type, set())
    return ext in {ext for exts in ALLOWED_EXTENSIONS.values() for ext in exts}

def get_file_type(file_path):
    mime = magic.Magic()
    file_type = mime.from_file(file_path)
    if 'image' in file_type.lower():
        return 'image'
    elif 'video' in file_type.lower():
        return 'video'
    elif 'audio' in file_type.lower():
        return 'audio'
    else:
        return 'document'

def save_file(file, upload_type='message'):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Generate unique filename
        unique_filename = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex}_{filename}"
        
        # Create upload directory if it doesn't exist
        upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], upload_type)
        os.makedirs(upload_dir, exist_ok=True)
        
        file_path = os.path.join(upload_dir, unique_filename)
        file.save(file_path)
        
        return {
            'filename': unique_filename,
            'file_type': get_file_type(file_path),
            'file_url': f'/uploads/{upload_type}/{unique_filename}'
        }
    return None

def delete_file(file_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
    except Exception as e:
        current_app.logger.error(f"Error deleting file {file_path}: {str(e)}")
    return False
