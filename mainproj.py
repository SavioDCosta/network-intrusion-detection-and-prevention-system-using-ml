import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
%matplotlib inline
import pandas.util.testing as tm
import tkinter as tk
import sklearn
from tkinter import *
from tkinter.ttk import *
from tkinter.filedialog import askopenfile
from tkinter.filedialog import askopenfilename
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import subprocess
from sklearn.model_selection import KFold

window = tk.Tk()
window.title("NIDS & PS Using ML")
window.geometry('500x400')

label1 = tk.Label(window, text='Select a test CSV File To Upload & Clean').grid(column=0,row=0)

file = None
testfinal = None

def open_file_unclean():   
    global file
    global testfinal
    #file = askopenfile(mode ='r', filetypes =[('CSV Files', '*.csv')])
    file = askopenfilename(filetypes =[('CSV Files', '*.csv')]) 
    if file is not None: 
        print(file)  
        label2 = tk.Label(window, text="Reading the CSV File").grid(column=0,row=2)
        testfinal = pd.read_csv(file)
        testfinal = testfinal.rename(columns={"Max packet Length": "Max Packet Length","Bwd Segment Size Avg": "Avg Bwd Segment Size","FWD Init Win Bytes": "Init_Win_bytes_forward","Fwd Seg Size Min": "min_seg_size_forward"})
        testfinal = testfinal.drop(['Dst Port','Flow ID','Src IP','Src Port','Dst IP','Protocol','Timestamp','Total Fwd Packet','Total Bwd packets','Total Length of Fwd Packet','Total Length of Bwd Packet','Fwd Packet Length Max','Fwd Packet Length Min','Fwd Packet Length Mean','Fwd Packet Length Std','Bwd Packet Length Min','Flow Bytes/s','Flow Packets/s','Bwd IAT Total','Fwd PSH Flags','Bwd PSH Flags','Fwd URG Flags','Bwd URG Flags','Fwd Packets/s','Packet Length Min','SYN Flag Count','RST Flag Count','URG Flag Count','CWE Flag Count','ECE Flag Count','Down/Up Ratio','Fwd Segment Size Avg','Fwd Bytes/Bulk Avg','Fwd Packet/Bulk Avg','Fwd Bulk Rate Avg','Bwd Bytes/Bulk Avg','Bwd Packet/Bulk Avg','Bwd Bulk Rate Avg','Subflow Fwd Packets','Subflow Fwd Bytes','Subflow Bwd Packets','Subflow Bwd Bytes','Bwd Init Win Bytes','Fwd Act Data Pkts'], axis=1)
        testfinal["Label"] = testfinal["Label"].replace("NeedManualLabel","")
        testfinal = testfinal.replace([np.inf, -np.inf], np.nan)
        testfinal = testfinal.replace('Infinite', np.nan)
        testfinal = testfinal.dropna()
        a = testfinal['Flow Duration'].dtypes
        for colname in list(testfinal):
            if testfinal[colname].dtype == np.float64:
                testfinal[colname] = testfinal[colname].astype('int64')
        testfinal.to_csv(file)
        testfinal = pd.read_csv(file)
        label3 = tk.Label(window, text="Cleaning Complete!").grid(column=0,row=3)
        label4 = tk.Label(window, text="Ready to train!").grid(column=0,row=3)

btn1 = Button(window, text ='Open', command = lambda:open_file_unclean()) 
btn1.grid(column=1, row=0) 

label5 = tk.Label(window, text='Select a test CSV File To Upload which is ready to train').grid(column=0,row=1)

def open_file_clean():
    global file
    global testfinal
    file = askopenfilename(filetypes =[('CSV Files', '*.csv')]) 
    label6 = tk.Label(window, text="Reading the CSV File").grid(column=0,row=2)
    if file is not None: 
        print(file)  
        testfinal = pd.read_csv(file)
        testfinal = testfinal.drop(testfinal.columns[[0]], axis=1)
        label7 = tk.Label(window, text="Ready to train").grid(column=0,row=3)
        
btn2 = Button(window, text ='Open', command = lambda:open_file_clean()) 
btn2.grid(column=1, row=1) 
                
label8 = tk.Label(window, text='Train the model').grid(column=0, row=5)

ddf = None
X = None
y = None
X_train = None
X_test = None
y_train = None
y_test = None
dtree = None
predictions = None
dec_accuracy = None
rfc = None
rfc_pred = None
rfc_accuracy = None
kf = None
def train_model_dec():
    global ddf
    global X
    global y
    global X_train 
    global X_test
    global y_train
    global y_test
    global dtree
    global predictions
    global dec_accuracy
    global rfc
    global rfc_pred
    global rfc_accuracy
    global kf
    ddf = pd.read_csv(r'C:\Users\dcost\Desktop\mainproj\main4.csv')
    ddf = ddf.drop(ddf.columns[[0]], axis=1)
    #if training and testing data are in the same dataframe
    X = ddf.drop('Label',axis=1)
    y = ddf['Label']
    kf = KFold(n_splits=10) # Define the split - into 2 folds 
    kf.get_n_splits(X) # returns the number of splitting iterations in the cross-validator
    print(kf) 
    for train_index, test_index in kf.split(X):
        print("TRAIN:", train_index, "TEST:", test_index)
        X_train, X_test = X.iloc[train_index], X.iloc[test_index]
        y_train, y_test = y.iloc[train_index], y.iloc[test_index]
    dtree = DecisionTreeClassifier()
    dtree.fit(X_train,y_train)
    predictions = dtree.predict(X_test)
    dec_accuracy = sklearn.metrics.accuracy_score(y_test, predictions, normalize=True, sample_weight=None)
    print(dec_accuracy)
    label9 = tk.Label(window, text="Click on Continue to Proceed ").grid(column=0,row=6)

btn3 = Button(window, text ='Train', command = lambda:train_model_dec()) 
btn3.grid(column=1, row=5)
    
def train_model_rfc():
    rfc = RandomForestClassifier(n_estimators=10)
    rfc.fit(X_train, y_train)
    rfc_pred = rfc.predict(X_test)
    rfc_accuracy = sklearn.metrics.accuracy_score(y_test, rfc_pred, normalize=True, sample_weight=None)
    print(rfc_accuracy)
    label10 = tk.Label(window, text="Training Complete").grid(column=0,row=7)
    
btn4 = Button(window, text ='Continue', command = lambda:train_model_rfc()) 
btn4.grid(column=2, row=5)

label11 = tk.Label(window, text='Scan the CSV').grid(column=0,row=8)

lableToAttackDict = None
list_pred = None
rfc_set = None
s = None

def scan_csv_dec():
    global s
    global lableToAttackDict
    s = testfinal.drop('Label',axis=1)
    dtree = DecisionTreeClassifier()
    dtree.fit(X_train,y_train)
    predictions = dtree.predict(s)
    print(set(predictions))
    label12 = tk.Label(window, text="Click on Continue to Proceed ").grid(column=0,row=9)
    
btn5 = Button(window, text ='Scan', command = lambda:scan_csv_dec()) 
btn5.grid(column=1, row=8)

def scan_csv_rfc():
    global list_pred
    global rfc_set
    global s
    rfc = RandomForestClassifier(n_estimators=10)
    rfc.fit(X_train, y_train)
    rfc_pred = rfc.predict(s)
    rfc_set = set(rfc_pred)
    print(rfc_set)
    list_pred = []
    lableToAttackDict = {0: 'BENIGN', 1: 'DoS Hulk', 2: 'PortScan', 3: 'DDoS', 4: 'DoS GoldenEye', 5: 'FTP-Patator', 6: 'SSH-Patator', 7: 'DoS slowloris', 8: 'DoS Slowhttptest'}
    for i in rfc_set:
        list_pred.append(lableToAttackDict.get(i))
    label13 = tk.Label(window, text=str(list_pred)).grid(column=0,row=10)    
    label14 = tk.Label(window, text="Scan Complete").grid(column=0,row=11)  
    
btn6 = Button(window, text ='Continue', command = lambda:scan_csv_rfc()) 
btn6.grid(column=2, row=8)

label15 = tk.Label(window, text='Do you want to Disconnect the internet connection? ').grid(column=0,row=12)

def net_disconnect():
    print(subprocess.call(["ipconfig", "/release", "*"], shell=True))
    label16 = tk.Label(window, text='Network Disconnected').grid(column=0,row=14)
    
btn7 = Button(window, text ='Disconnect', command = lambda:net_disconnect()) 
btn7.grid(column=0, row=13)

def net_connect():
    print(subprocess.call(["ipconfig", "/renew"], shell=True))
    label17 = tk.Label(window, text='Network Reconnected').grid(column=1,row=14)
    
btn8 = Button(window, text ='Connect', command = lambda:net_connect()) 
btn8.grid(column=1, row=13)

btn9 = Button(window, text ='Exit', command = lambda:window.destroy()) 
btn9.grid(column=0, row=15)

window.mainloop()