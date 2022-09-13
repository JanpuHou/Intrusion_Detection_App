import pandas as pd
import numpy as np
from sklearn.preprocessing import OneHotEncoder
from tensorflow.keras.models import load_model
import datetime as dt
import streamlit as st
import matplotlib.pyplot as plt
from PIL import Image, ImageOps


st.set_page_config(
     page_title="Network Intrustion Detection System",
     page_icon="🧊",
     layout="wide",
     initial_sidebar_state="expanded",
     menu_items={
         'About': "https://www.caloudi.com/"
     }
 )
st.title("AI-Assisted Network Intrustion Detection System")

image = Image.open('app_ids.jpg')
# st.image(image, caption='How This App Interpret Your Network Profile')
st.image(image,"Upload a Network Triffic Profile for Intrusion Detection" )


uploaded_file = st.file_uploader("Choose a Network Traffic Profile file ...", type="csv")

if uploaded_file is None:
    dfx = pd.read_csv(r'normal_data.csv', header=None)
else:
    dfx = pd.read_csv(uploaded_file)
    st.write(dfx)



uncode_df=dfx


model = load_model('my_kdd_model.h5')


def encode_network_data(dfx):
    df = pd.read_csv(r'kddcup_data.csv', header=None)
    df.columns = [
    'duration',
    'protocol_type',
    'service',
    'flag',
    'src_bytes',
    'dst_bytes',
    'land',
    'wrong_fragment',
    'urgent',
    'hot',
    'num_failed_logins',
    'logged_in',
    'num_compromised',
    'root_shell',
    'su_attempted',
    'num_root',
    'num_file_creations',
    'num_shells',
    'num_access_files',
    'num_outbound_cmds',
    'is_host_login',
    'is_guest_login',
    'count',
    'srv_count',
    'serror_rate',
    'srv_serror_rate',
    'rerror_rate',
    'srv_rerror_rate',
    'same_srv_rate',
    'diff_srv_rate',
    'srv_diff_host_rate',
    'dst_host_count',
    'dst_host_srv_count',
    'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate',
    'dst_host_srv_serror_rate',
    'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate']

    oe_protocol = OneHotEncoder()
    oe_results = oe_protocol.fit_transform(df[["protocol_type"]])
    oe_dfx = oe_protocol.transform(dfx[["protocol_type"]])
    dfx1_P=pd.DataFrame(oe_dfx.toarray(), columns=oe_protocol.categories_)
#print(dfx1_P.head())
    dfx = dfx.join(dfx1_P)
#print(dfx.head())

    oe_service = OneHotEncoder()
    oe_results = oe_service.fit_transform(df[["service"]])
    oe_dfx = oe_service.transform(dfx[["service"]])
    dfx1_S=pd.DataFrame(oe_dfx.toarray(), columns=oe_service.categories_)
#print(dfx1_S.head())
    dfx = dfx.join(dfx1_S)
#print(dfx.head())


    oe_flag = OneHotEncoder()
    oe_results = oe_flag.fit_transform(df[["flag"]])
    oe_dfx = oe_flag.transform(dfx[["flag"]])
    dfx1_F=pd.DataFrame(oe_dfx.toarray(), columns=oe_flag.categories_)
#print(dfx1_S.head())
    dfx = dfx.join(dfx1_F)
#print(dfx.head())
    dfx=dfx.drop(['protocol_type','service','flag'], axis=1)
    return dfx


dfx.columns = [
    'duration',
    'protocol_type',
    'service',
    'flag',
    'src_bytes',
    'dst_bytes',
    'land',
    'wrong_fragment',
    'urgent',
    'hot',
    'num_failed_logins',
    'logged_in',
    'num_compromised',
    'root_shell',
    'su_attempted',
    'num_root',
    'num_file_creations',
    'num_shells',
    'num_access_files',
    'num_outbound_cmds',
    'is_host_login',
    'is_guest_login',
    'count',
    'srv_count',
    'serror_rate',
    'srv_serror_rate',
    'rerror_rate',
    'srv_rerror_rate',
    'same_srv_rate',
    'diff_srv_rate',
    'srv_diff_host_rate',
    'dst_host_count',
    'dst_host_srv_count',
    'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate',
    'dst_host_srv_serror_rate',
    'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate']
print(dfx.head())
print(dfx.shape)

dfx=encode_network_data(dfx)
print(dfx.head())
print(dfx.shape)
x_columns = dfx.columns
x = dfx[x_columns].values


labels=['back.' ,'buffer_overflow.' ,'ftp_write.', 'guess_passwd.', 'imap.','ipsweep.' ,'land.', 'loadmodule.', 'multihop.' ,'neptune.', 'nmap.' ,'normal.','perl.' ,'phf.' ,'pod.', 'portsweep.', 'rootkit.', 'satan.', 'smurf.', 'spy.','teardrop.' ,'warezclient.', 'warezmaster.']         
pred = model.predict(x)

for i in range(10):
    my_list=pred[i].tolist()
    indx=my_list.index(max(my_list))
    ts=(dt.datetime.now())
    if indx == 11: 
       st.write(ts, 'Your Network Behavor Normal Now........')
    else:
       st.write(ts,'Act Now!!! Your network is under ',labels[indx],' ATTACK!')
       st.error('Warning::Your Network is under ATTACK!')
       
       
df=uncode_df

# Look at the numerical data

fig, axs = plt.subplots(2, 2)
axs[0, 0].plot(df['src_bytes'].head(500))
axs[0, 0].set_title('F5: scr_bytes')
axs[0, 1].plot(df['dst_bytes'].head(500))
axs[0, 1].set_title('F6: dst_bytes')
axs[1, 0].plot(df['dst_host_count'].head(500))
axs[1, 0].set_title('F31: dst_host_count')
axs[1, 1].plot(df['dst_host_same_src_port_rate'].head(500))
axs[1, 1].set_title('F36: dst_host_same_src_port_rat')
for ax in axs.flat:
    ax.set(xlabel='Time(Minutes)', ylabel='Enterprise Network Log')

# Hide x labels and tick labels for top plots and y ticks for right plots.
for ax in axs.flat:
    ax.label_outer()
  
fig.suptitle('Data Samples from Network Traffic Profile: Numerical Features')
#plt.show()
st.write(fig)              