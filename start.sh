#!/bin/bash
python create_db.py
gunicorn --bind 0.0.0.0:$PORT app:app
