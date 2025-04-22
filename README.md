## Install dependencies
```sh
pip install fastapi uvicorn sqlalchemy pydantic python-jose passlib python-multipart
```
```sh
pip install bcrypt==4.0.1
```
## Run

```sh
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
