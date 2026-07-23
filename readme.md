# Secure Coding Market

Flask 기반 중고 거래 플랫폼 예제입니다. 사용자 인증, 상품 등록/조회/구매, 관리자 기능, CSRF 보호, Socket.IO 실시간 채팅을 포함합니다.

## 요구 사항

- Python 3.9
- Flask
- Flask-SocketIO
- Flask-SQLAlchemy

## 환경 설정

### conda 사용 시
```bash
conda env create -f enviroments.yaml
conda activate secure_coding
```

### venv + pip 사용 시
```bash
python -m venv venv
venv\Scripts\activate
pip install flask flask-socketio flask-sqlalchemy
```

## 실행 방법

```bash
python app.py
```

서버가 시작되면 브라우저에서 다음 주소로 접속합니다:

- http://127.0.0.1:5000

## 옵션

- `SECRET_KEY` 환경 변수를 설정하면 세션 보안이 강화됩니다.
- 개발 환경에서는 `app.py`에서 `SESSION_COOKIE_SECURE = False`로 설정되어 있습니다. HTTPS 환경에서는 `True`로 변경해야 합니다.

## 주요 파일

- `app.py` - Flask 앱, 라우트, 데이터베이스 및 Socket.IO 이벤트 정의
- `templates/` - Jinja2 HTML 템플릿
- `static/` - CSS, JavaScript, Socket.IO 클라이언트 파일
- `enviroments.yaml` - conda 환경 정의

## 참고

- `static/socket.io.js`는 동일 출처의 Socket.IO 클라이언트를 로컬에서 제공하기 위해 포함되어 있습니다.
- `market.db` 파일이 이미 존재하며, 데이터베이스 초기화는 `app.py`에서 자동으로 수행됩니다.
