#encoding=utf-8
import os
import uuid
import MySQLdb
from config import HOSTNAME,PASSWORD,USER,PORT,DATABASE
from flask import Flask,g,render_template,flash
from flask.globals import request
from _sha256 import sha256
from flask.templating import render_template
from sqlalchemy.sql.expression import false

app=Flask(__name__)
app.secret_key="123456"
def connect_db():
    db=MySQLdb.connect(host=HOSTNAME,port=PORT,user=USER,passwd=PASSWORD)
    #cursor=db.cursor()
    #sql="select detection_name from mts_pattern.signature where id<300"
    #cursor.execute(sql)
    #res=cursor.fetchall()
    #for res1 in res:
        #print res1
    return db
def get_db():
    if not hasattr(g,'db'):
        g.db=connect_db()
    return g.db
@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()
@app.route('/')
def index():
    get_db()
    return render_template('show.html')

@app.route('/result',methods=['GET','POST'])
def add_sigpot():
    analyster_name=request.form['analysts']
    #print analyster_name
    if analyster_name=="none":
        flash("Analysts not selected please select again")
        return  render_template('show.html')
    choice_type=request.form['choice']
    textarea=request.form['textarea']
    '''
    1.在signature表里找到并成功删除
    2.在signature表里找到但并没成功删除
    3.没有在signature表里找到
    '''
    signature_found_deleted=[]
    signature_found_not_deleted=[]
    signature_not_found=[]
    #print analyster_name+" 1"
    #print choice_type+" 2"
    #print textarea+" 3"
    group_id=uuid.uuid1()
    textarea_split=textarea.split('\n')
    for text in textarea_split:
        #去除可能存在的引号字符
        sha_256=text.strip("'")
        result=search_signature(sha_256)
        #print text.strip()+analyster_name
        insert_sigpot(result,analyster_name,group_id)
        is_exist=result['is_exist']
        if is_exist==1:
            is_deleted=delete_signature(sha_256)
            if is_deleted==True:
                signature_found_deleted.append(sha_256)
            else:
                signature_found_not_deleted.append(sha_256)
        else:
            signature_not_found.append(sha_256)
    signature_found_deleted_length=len(signature_found_deleted)
    signature_found_not_deleted_length=len(signature_found_not_deleted)
    signature_not_found_length=len(signature_not_found)
    
    return render_template('result.html',signature_found_deleted=signature_found_deleted,
                           signature_found_not_deleted=signature_found_not_deleted,
                           signature_not_found=signature_not_found,
                           signature_found_deleted_length=signature_found_deleted_length,
                           signature_found_not_deleted_length=signature_found_not_deleted_length,
                           signature_not_found_length=signature_not_found_length)   


#在表signature里面搜索sha256
@app.route('/search')
def search_signature(sha_256):
    get_db()
    cursor=g.db.cursor()
    sql="select detection_name from recommend.signature where sha256='%s';"%(sha_256)
    cursor.execute(sql)
    canrows=cursor.fetchall()
    #判断该sha256是否存在
    if len(canrows)==0:
        is_exist=0
        detection_name=None
    else:
        is_exist=1
        for canrow in canrows:
            detection_name=canrow[0]
    result={
            'sha_256':sha_256,
            'detection_name':detection_name,
            'is_exist':is_exist
         }
    return result

def insert_sigpot(result,analyster_name,group_id):
    sha_256=result['sha_256']
    detection_name=result['detection_name']
    is_exist=result['is_exist']
    
    get_db()
    cursor=g.db.cursor()
    sql="insert into %s.sigopt_portal(group_id,sha256,detection_name,analysts_name,is_exist,time) values('%s','%s','%s','%s','%s',current_timestamp)"%(DATABASE,group_id,sha_256,detection_name,analyster_name,is_exist)
    cursor.execute(sql)
    g.db.commit()        

def delete_signature(sha_256):
    get_db()
    cursor=g.db.cursor()
    sql="delete from %s.signature where sha256='%s';"%(DATABASE,sha_256)
    #print sql
    cursor.execute(sql)
    g.db.commit()
    sql="select * from %s.signature where sha256='%s';"%(DATABASE,sha_256)
    cursor.execute(sql)
    canrows=cursor.fetchall()
    #判断该sha256是否成功删除
    if len(canrows)==0:
        is_deleted=True   
    else:
        is_deleted=False
    return is_deleted
if __name__=='__main__':
    
    app.run(debug=True)


