# apps/config.py
import os

if os.environ.get('RENDER', None) != 'true':
    # render.com이 아닌 로컬 환경에서만 .env를 로드(안해도 됨)
    from dotenv import load_dotenv
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    dotenv_path = os.path.join(BASE_DIR, '..', '.env')
    load_dotenv(dotenv_path)

class Config:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SECRET_KEY = os.getenv('SECRET_KEY')
    #API_KEY = os.getenv('API_KEY')

