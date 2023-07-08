from . import db
from sqlalchemy import create_engine
from sqlalchemy.engine.url import URL
import cryptography
import pymysql
import pandas as pd
from enum import Enum
import string
import random


def generate_uique_id():
    length = 25

    while True:
        id = ''.join(random.choices(string.ascii_letters, k=length))
        # if objects.filter(code=id).count() == 0:
        #     return code

class TABLENAMES(Enum):
    EMAIL              = 'email'
    PASSWORD              = 'password'


class User(db.Model):
    __tablename__='User'
    __table_args__ = {'mysql_engine':'InnoDB', 'mysql_charset':'utf8mb4','mysql_collate':'utf8mb4_0900_ai_ci'}
    id=db.Column('idUser', db.Integer, primary_key=True)
    email=db.Column('email', db.String(100))
    password=db.Column('password', db.String(100))

    def __init__(self, email, password):
        print(f'user: {email} pass: {password}')
        self.email=email
        self.password=password

    def __repr__(self):
        return self.email