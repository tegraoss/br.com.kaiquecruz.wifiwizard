/*
 * Copyright 2015 Matt Parsons
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package br.com.kaiquecruz.wifiwizard;

import org.apache.cordova.*;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiEnterpriseConfig;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.SupplicantState;
import android.content.Context;
import android.util.Log;


public class WifiWizard extends CordovaPlugin {
    
    private static final String ADD_NETWORK = "addNetwork";
    private static final String REMOVE_NETWORK = "removeNetwork";
    private static final String CONNECT_NETWORK = "connectNetwork";
    private static final String DISCONNECT_NETWORK = "disconnectNetwork";
    private static final String DISCONNECT = "disconnect";
    private static final String LIST_NETWORKS = "listNetworks";
    private static final String START_SCAN = "startScan";
    private static final String GET_SCAN_RESULTS = "getScanResults";
    private static final String GET_CONNECTED_SSID = "getConnectedSSID";
    private static final String GET_CONNECTED_BSSID = "getConnectedBSSID";
    private static final String IS_WIFI_ENABLED = "isWifiEnabled";
    private static final String SET_WIFI_ENABLED = "setWifiEnabled";
    private static final String SAVE_EAP_CONFIG = "saveEapConfig";
    private static final String TAG = "WifiWizard";
    
    private WifiManager wifiManager;
    private CallbackContext callbackContext;
    
    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        this.wifiManager = (WifiManager) cordova.getActivity().getSystemService(Context.WIFI_SERVICE);
    }
    
    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext)
      throws JSONException {
        
        this.callbackContext = callbackContext;
        
        if(action.equals(IS_WIFI_ENABLED)) {
            return this.isWifiEnabled(callbackContext);
        }
        else if(action.equals(SET_WIFI_ENABLED)) {
            return this.setWifiEnabled(callbackContext, data);
        }
        else if (!wifiManager.isWifiEnabled()) {
            callbackContext.error("Wifi is not enabled.");
            return false;
        }
        else if(action.equals(ADD_NETWORK)) {
            return this.addNetwork(callbackContext, data);
        }
        else if(action.equals(REMOVE_NETWORK)) {
            return this.removeNetwork(callbackContext, data);
        }
        else if(action.equals(CONNECT_NETWORK)) {
            return this.connectNetwork(callbackContext, data);
        }
        else if(action.equals(DISCONNECT_NETWORK)) {
            return this.disconnectNetwork(callbackContext, data);
        }
        else if(action.equals(LIST_NETWORKS)) {
            return this.listNetworks(callbackContext);
        }
        else if(action.equals(START_SCAN)) {
            return this.startScan(callbackContext);
        }
        else if(action.equals(GET_SCAN_RESULTS)) {
            return this.getScanResults(callbackContext, data);
        }
        else if(action.equals(DISCONNECT)) {
            return this.disconnect(callbackContext);
        }
        else if(action.equals(GET_CONNECTED_SSID)) {
            return this.getConnectedSSID(callbackContext);
        }
        else if(action.equals(GET_CONNECTED_BSSID)) {
            return this.getConnectedBSSID(callbackContext);
        }
        else if(action.equals(SAVE_EAP_CONFIG)) {
            return this.saveEapConfig(callbackContext);
        }
        else {
            callbackContext.error("Incorrect action parameter: " + action);
        }
        
        return false;
    }
    
    /**
     * This methods adds a network to the list of available WiFi networks.
     * If the network already exists, then it updates it.
     *
     * @params callbackContext     A Cordova callback context.
     * @params data                JSON Array with [0] == SSID, [1] == password
     * @return true    if add successful, false if add fails
     */
    private boolean addNetwork(CallbackContext callbackContext, JSONArray data) {
        // Initialize the WifiConfiguration object
        WifiConfiguration wifi = new WifiConfiguration();
        
        Log.d(TAG, "WifiWizard: addNetwork entered.");
        
        try {
            // data's order for ANY object is 0: ssid, 1: authentication algorithm,
            // 2+: authentication information.
            String authType = data.getString(1);
            
            
            if (authType.equals("WPA")) {
                // WPA Data format:
                // 0: ssid
                // 1: auth
                // 2: password
                String newSSID = data.getString(0);
                wifi.SSID = newSSID;
                String newPass = data.getString(2);
                wifi.preSharedKey = newPass;
                
                wifi.status = WifiConfiguration.Status.ENABLED;
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
                wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
                wifi.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
                wifi.allowedProtocols.set(WifiConfiguration.Protocol.WPA);
                
                wifi.networkId = ssidToNetworkId(newSSID);
                
                if ( wifi.networkId == -1 ) {
                    wifiManager.addNetwork(wifi);
                    callbackContext.success(newSSID + " successfully added.");
                }
                else {
                    wifiManager.updateNetwork(wifi);
                    callbackContext.success(newSSID + " successfully updated.");
                }
                
                wifiManager.saveConfiguration();
                return true;
            }
            else if (authType.equals("WEP")) {
                // TODO: connect/configure for WEP
                Log.d(TAG, "WEP unsupported.");
                callbackContext.error("WEP unsupported");
                return false;
            }
            else if (authType.equals("NONE")) {
                String newSSID = data.getString(0);
                wifi.SSID = newSSID;
                wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
                wifi.networkId = ssidToNetworkId(newSSID);
                
                if ( wifi.networkId == -1 ) {
                    wifiManager.addNetwork(wifi);
                    callbackContext.success(newSSID + " successfully added.");
                }
                else {
                    wifiManager.updateNetwork(wifi);
                    callbackContext.success(newSSID + " successfully updated.");
                }
                
                wifiManager.saveConfiguration();
                return true;
            }
            // TODO: Add more authentications as necessary
            else {
                Log.d(TAG, "Wifi Authentication Type Not Supported.");
                callbackContext.error("Wifi Authentication Type Not Supported: " + authType);
                return false;
            }
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG,e.getMessage());
            return false;
        }
    }
    
    /**
     *    This method removes a network from the list of configured networks.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to remove
     *    @return    true if network removed, false if failed
     */
    private boolean removeNetwork(CallbackContext callbackContext, JSONArray data) {
        Log.d(TAG, "WifiWizard: removeNetwork entered.");
        
        if(!validateData(data)) {
            callbackContext.error("WifiWizard: removeNetwork data invalid");
            Log.d(TAG, "WifiWizard: removeNetwork data invalid");
            return false;
        }
        
        // TODO: Verify the type of data!
        try {
            String ssidToDisconnect = data.getString(0);
            
            int networkIdToRemove = ssidToNetworkId(ssidToDisconnect);
            
            if (networkIdToRemove >= 0) {
                wifiManager.removeNetwork(networkIdToRemove);
                wifiManager.saveConfiguration();
                callbackContext.success("Network removed.");
                return true;
            }
            else {
                callbackContext.error("Network not found.");
                Log.d(TAG, "WifiWizard: Network not found, can't remove.");
                return false;
            }
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }
    }
    
    /**
     *    This method connects a network.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to connect
     *    @return    true if network connected, false if failed
     */
    private boolean connectNetwork(CallbackContext callbackContext, JSONArray data) {
        Log.d(TAG, "WifiWizard: connectNetwork entered.");
        if(!validateData(data)) {
            callbackContext.error("WifiWizard: connectNetwork invalid data");
            Log.d(TAG, "WifiWizard: connectNetwork invalid data.");
            return false;
        }
        String ssidToConnect = "";
        
        try {
            ssidToConnect = data.getString(0);
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }
        
        int networkIdToConnect = ssidToNetworkId(ssidToConnect);
        
        if (networkIdToConnect >= 0) {
            // We disable the network before connecting, because if this was the last connection before
            // a disconnect(), this will not reconnect.
            wifiManager.disableNetwork(networkIdToConnect);
            wifiManager.enableNetwork(networkIdToConnect, true);
            
            SupplicantState supState;
            WifiInfo wifiInfo = wifiManager.getConnectionInfo();
            supState = wifiInfo.getSupplicantState();
            callbackContext.success(supState.toString());
            return true;
            
        }else{
            callbackContext.error("WifiWizard: cannot connect to network");
            return false;
        }
    }
    
    /**
     *    This method disconnects a network.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to connect
     *    @return    true if network disconnected, false if failed
     */
    private boolean disconnectNetwork(CallbackContext callbackContext, JSONArray data) {
        Log.d(TAG, "WifiWizard: disconnectNetwork entered.");
        if(!validateData(data)) {
            callbackContext.error("WifiWizard: disconnectNetwork invalid data");
            Log.d(TAG, "WifiWizard: disconnectNetwork invalid data");
            return false;
        }
        String ssidToDisconnect = "";
        // TODO: Verify type of data here!
        try {
            ssidToDisconnect = data.getString(0);
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }
        
        int networkIdToDisconnect = ssidToNetworkId(ssidToDisconnect);
        
        if (networkIdToDisconnect > 0) {
            wifiManager.disableNetwork(networkIdToDisconnect);
            callbackContext.success("Network " + ssidToDisconnect + " disconnected!");
            return true;
        }
        else {
            callbackContext.error("Network " + ssidToDisconnect + " not found!");
            Log.d(TAG, "WifiWizard: Network not found to disconnect.");
            return false;
        }
    }
    
    /**
     *    This method disconnects current network.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if network disconnected, false if failed
     */
    private boolean disconnect(CallbackContext callbackContext) {
        Log.d(TAG, "WifiWizard: disconnect entered.");
        if (wifiManager.disconnect()) {
            callbackContext.success("Disconnected from current network");
            return true;
        } else {
            callbackContext.error("Unable to disconnect from the current network");
            return false;
        }
    }
    
    /**
     *    This method uses the callbackContext.success method to send a JSONArray
     *    of the currently configured networks.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                JSON Array, with [0] being SSID to connect
     *    @return    true if network disconnected, false if failed
     */
    private boolean listNetworks(CallbackContext callbackContext) {
        Log.d(TAG, "WifiWizard: listNetworks entered.");
        List<WifiConfiguration> wifiList = wifiManager.getConfiguredNetworks();
        
        JSONArray returnList = new JSONArray();
        
        for (WifiConfiguration wifi : wifiList) {
            returnList.put(wifi.SSID);
        }
        
        callbackContext.success(returnList);
        
        return true;
    }
    
    /**
     *    This method uses the callbackContext.success method to send a JSONArray
     *    of the scanned networks.
     *
     *    @param    callbackContext        A Cordova callback context
     *    @param    data                   JSONArray with [0] == JSONObject
     *    @return    true
     */
    private boolean getScanResults(CallbackContext callbackContext, JSONArray data) {
        List<ScanResult> scanResults = wifiManager.getScanResults();
        
        JSONArray returnList = new JSONArray();
        
        Integer numLevels = null;
        
        if(!validateData(data)) {
            callbackContext.error("WifiWizard: disconnectNetwork invalid data");
            Log.d(TAG, "WifiWizard: disconnectNetwork invalid data");
            return false;
        }else if (!data.isNull(0)) {
            try {
                JSONObject options = data.getJSONObject(0);
                
                if (options.has("numLevels")) {
                    Integer levels = options.optInt("numLevels");
                    
                    if (levels > 0) {
                        numLevels = levels;
                    } else if (options.optBoolean("numLevels", false)) {
                        // use previous default for {numLevels: true}
                        numLevels = 5;
                    }
                }
            } catch (JSONException e) {
                e.printStackTrace();
                callbackContext.error(e.toString());
                return false;
            }
        }
        
        for (ScanResult scan : scanResults) {
            /*
             * @todo - breaking change, remove this notice when tidying new release and explain changes, e.g.:
             *   0.y.z includes a breaking change to WifiWizard.getScanResults().
             *   Earlier versions set scans' level attributes to a number derived from wifiManager.calculateSignalLevel.
             *   This update returns scans' raw RSSI value as the level, per Android spec / APIs.
             *   If your application depends on the previous behaviour, we have added an options object that will modify behaviour:
             *   - if `(n == true || n < 2)`, `*.getScanResults({numLevels: n})` will return data as before, split in 5 levels;
             *   - if `(n > 1)`, `*.getScanResults({numLevels: n})` will calculate the signal level, split in n levels;
             *   - if `(n == false)`, `*.getScanResults({numLevels: n})` will use the raw signal level;
             */
            
            int level;
            
            if (numLevels == null) {
                level = scan.level;
            } else {
                level = wifiManager.calculateSignalLevel(scan.level, numLevels);
            }
            
            JSONObject lvl = new JSONObject();
            try {
                lvl.put("level", level);
                lvl.put("SSID", scan.SSID);
                lvl.put("BSSID", scan.BSSID);
                lvl.put("frequency", scan.frequency);
                lvl.put("capabilities", scan.capabilities);
                // lvl.put("timestamp", scan.timestamp);
                returnList.put(lvl);
            } catch (JSONException e) {
                e.printStackTrace();
                callbackContext.error(e.toString());
                return false;
            }
        }
        
        callbackContext.success(returnList);
        return true;
    }
    
    /**
     *    This method uses the callbackContext.success method. It starts a wifi scanning
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if started was successful
     */
    private boolean startScan(CallbackContext callbackContext) {
        if (wifiManager.startScan()) {
            callbackContext.success();
            return true;
        }
        else {
            callbackContext.error("Scan failed");
            return false;
        }
    }
    
    /**
     * This method retrieves the SSID for the currently connected network
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if SSID found, false if not.
     */
    private boolean getConnectedSSID(CallbackContext callbackContext){
        if(!wifiManager.isWifiEnabled()){
            callbackContext.error("Wifi is disabled");
            return false;
        }
        
        WifiInfo info = wifiManager.getConnectionInfo();
        
        if(info == null){
            callbackContext.error("Unable to read wifi info");
            return false;
        }
        
        String ssid = info.getSSID();
        if(ssid.isEmpty()) {
            ssid = info.getBSSID();
        }
        if(ssid.isEmpty()){
            callbackContext.error("SSID is empty");
            return false;
        }
        
        callbackContext.success(ssid);
        return true;
    }
    
    /**
     * This method retrieves the BSSID for the currently connected network
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if SSID found, false if not.
     */
    private boolean getConnectedBSSID(CallbackContext callbackContext){
        if(!wifiManager.isWifiEnabled()){
            callbackContext.error("Wifi is disabled");
            return false;
        }
        
        WifiInfo info = wifiManager.getConnectionInfo();
        
        if(info == null){
            callbackContext.error("Unable to read wifi info");
            return false;
        }
        
        String ssid = info.getBSSID();
        
        if(ssid.isEmpty()){
            callbackContext.error("SSID is empty");
            return false;
        }
        
        callbackContext.success(ssid);
        return true;
    }
    
    
    
    /**
     * This method retrieves the current WiFi status
     *
     *    @param    callbackContext        A Cordova callback context
     *    @return    true if WiFi is enabled, fail will be called if not.
     */
    private boolean isWifiEnabled(CallbackContext callbackContext) {
        boolean isEnabled = wifiManager.isWifiEnabled();
        callbackContext.success(isEnabled ? "1" : "0");
        return isEnabled;
    }
    
    /**
     *    This method takes a given String, searches the current list of configured WiFi
     *     networks, and returns the networkId for the network if the SSID matches. If not,
     *     it returns -1.
     */
    private int ssidToNetworkId(String ssid) {
        List<WifiConfiguration> currentNetworks = wifiManager.getConfiguredNetworks();
        int networkId = -1;
        
        // For each network in the list, compare the SSID with the given one
        for (WifiConfiguration test : currentNetworks) {
            if ( test.SSID.equals(ssid) ) {
                networkId = test.networkId;
            }
        }
        
        return networkId;
    }
    
    /**
     *    This method enables or disables the wifi
     */
    private boolean setWifiEnabled(CallbackContext callbackContext, JSONArray data) {
        if(!validateData(data)) {
            callbackContext.error("WifiWizard: disconnectNetwork invalid data");
            Log.d(TAG, "WifiWizard: disconnectNetwork invalid data");
            return false;
        }
        
        String status = "";
        
        try {
            status = data.getString(0);
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }
        
        if (wifiManager.setWifiEnabled(status.equals("true"))) {
            callbackContext.success();
            return true;
        }
        else {
            callbackContext.error("Cannot enable wifi");
            return false;
        }
    }
    
    private boolean validateData(JSONArray data) {
        try {
            if (data == null || data.get(0) == null) {
                callbackContext.error("Data is null.");
                return false;
            }
            return true;
        }
        catch (Exception e) {
            callbackContext.error(e.getMessage());
        }
        return false;
    }
    

    private boolean saveEapConfig(CallbackContext callbackContext, JSONArray data) {
        /********************************Configuration Strings****************************************************/
        final String ENTERPRISE_EAP = "TLS";
        final String ENTERPRISE_CLIENT_CERT = "keystore://USRCERT_CertificateName";
        final String ENTERPRISE_PRIV_KEY = "USRPKEY_CertificateName";
        //CertificateName = Name given to the certificate while installing it

        /*Optional Params- My wireless Doesn't use these*/
        final String ENTERPRISE_PHASE2 = "";
        final String ENTERPRISE_ANON_IDENT = "ABC";
        final String ENTERPRISE_CA_CERT = ""; // If required: "keystore://CACERT_CaCertificateName"
        /********************************Configuration Strings****************************************************/

        /*Create a WifiConfig*/
        WifiConfiguration selectedConfig = new WifiConfiguration();

        /*AP Name*/
        selectedConfig.SSID = data.getString(0);

        /*Priority*/
        selectedConfig.priority = 40;

        /*Enable Hidden SSID*/
        selectedConfig.hiddenSSID = true;

        /*Key Mgmnt*/
        selectedConfig.allowedKeyManagement.clear();
        selectedConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.IEEE8021X);
        selectedConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP);

        /*Group Ciphers*/
        selectedConfig.allowedGroupCiphers.clear();
        selectedConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
        selectedConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
        selectedConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
        selectedConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);

        /*Pairwise ciphers*/
        selectedConfig.allowedPairwiseCiphers.clear();
        selectedConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
        selectedConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);

        /*Protocols*/
        selectedConfig.allowedProtocols.clear();
        selectedConfig.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
        selectedConfig.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

        // Enterprise Settings
        // Reflection magic here too, need access to non-public APIs
        try {
            // Let the magic start
            Class[] wcClasses = WifiConfiguration.class.getClasses();
            // null for overzealous java compiler
            Class wcEnterpriseField = null;

            for (Class wcClass : wcClasses)
                if (wcClass.getName().equals(INT_ENTERPRISEFIELD_NAME)) {
                    wcEnterpriseField = wcClass;
                    break;
                }
            boolean noEnterpriseFieldType = false; 
            if(wcEnterpriseField == null)
                noEnterpriseFieldType = true; // Cupcake/Donut access enterprise settings directly

            Field wcefAnonymousId = null, wcefCaCert = null, wcefClientCert = null, wcefEap = null, wcefIdentity = null, wcefPassword = null, wcefPhase2 = null, wcefPrivateKey = null, wcefEngine = null, wcefEngineId = null;
            Field[] wcefFields = WifiConfiguration.class.getFields();
            // Dispatching Field vars
            for (Field wcefField : wcefFields) {
                if (wcefField.getName().equals(INT_ANONYMOUS_IDENTITY))
                    wcefAnonymousId = wcefField;
                else if (wcefField.getName().equals(INT_CA_CERT))
                    wcefCaCert = wcefField;
                else if (wcefField.getName().equals(INT_CLIENT_CERT))
                    wcefClientCert = wcefField;
                else if (wcefField.getName().equals(INT_EAP))
                    wcefEap = wcefField;
                else if (wcefField.getName().equals(INT_IDENTITY))
                    wcefIdentity = wcefField;
                else if (wcefField.getName().equals(INT_PASSWORD))
                    wcefPassword = wcefField;
                else if (wcefField.getName().equals(INT_PHASE2))
                    wcefPhase2 = wcefField;
                else if (wcefField.getName().equals(INT_PRIVATE_KEY))
                    wcefPrivateKey = wcefField;
                else if (wcefField.getName().equals("engine"))
                    wcefEngine = wcefField;
                else if (wcefField.getName().equals("engine_id"))
                    wcefEngineId = wcefField;
            }


            Method wcefSetValue = null;
            if(!noEnterpriseFieldType){
            for(Method m: wcEnterpriseField.getMethods())
                //System.out.println(m.getName());
                if(m.getName().trim().equals("setValue"))
                    wcefSetValue = m;
            }


            /*EAP Method*/
            if(!noEnterpriseFieldType) {
                wcefSetValue.invoke(wcefEap.get(selectedConfig), ENTERPRISE_EAP);
            }
            else {
                wcefEap.set(selectedConfig, ENTERPRISE_EAP);
            }
            /*EAP Phase 2 Authentication*/
            if(!noEnterpriseFieldType) {
                wcefSetValue.invoke(wcefPhase2.get(selectedConfig), ENTERPRISE_PHASE2);
            }
            else {
                wcefPhase2.set(selectedConfig, ENTERPRISE_PHASE2);
            }
            /*EAP Anonymous Identity*/
            if(!noEnterpriseFieldType) {
                wcefSetValue.invoke(wcefAnonymousId.get(selectedConfig), ENTERPRISE_ANON_IDENT);
            }
            else {
                wcefAnonymousId.set(selectedConfig, ENTERPRISE_ANON_IDENT);
            }
            /*EAP CA Certificate*/
            if(!noEnterpriseFieldType) {
                wcefSetValue.invoke(wcefCaCert.get(selectedConfig), ENTERPRISE_CA_CERT);
            }
            else {
                wcefCaCert.set(selectedConfig, ENTERPRISE_CA_CERT);
            }               
            /*EAP Private key*/
            if(!noEnterpriseFieldType)  {
                wcefSetValue.invoke(wcefPrivateKey.get(selectedConfig), ENTERPRISE_PRIV_KEY);
            }
            else {
                wcefPrivateKey.set(selectedConfig, ENTERPRISE_PRIV_KEY);
            }               
            /*EAP Identity*/
            if(!noEnterpriseFieldType) {
                wcefSetValue.invoke(wcefIdentity.get(selectedConfig), data.getString(1));
            }
            else {
                wcefIdentity.set(selectedConfig, data.getString(1));
            }               
            /*EAP Password*/
            if(!noEnterpriseFieldType) {
                wcefSetValue.invoke(wcefPassword.get(selectedConfig), data.getString(2));
            }
            else {
                wcefPassword.set(selectedConfig, data.getString(2));
            }               
            /*EAp Client certificate*/
            if(!noEnterpriseFieldType) {
                wcefSetValue.invoke(wcefClientCert.get(selectedConfig), ENTERPRISE_CLIENT_CERT);
            }
            else {
                wcefClientCert.set(selectedConfig, ENTERPRISE_CLIENT_CERT);
            }
            /*Engine fields*/
            if(!noEnterpriseFieldType) {
                wcefSetValue.invoke(wcefEngine.get(wifiConf), "1");
                wcefSetValue.invoke(wcefEngineId.get(wifiConf), "keystore");
            }

            // Adhoc for CM6
            // if non-CM6 fails gracefully thanks to nested try-catch

            try {
                Field wcAdhoc = WifiConfiguration.class.getField("adhocSSID");
                Field wcAdhocFreq = WifiConfiguration.class.getField("frequency");
                //wcAdhoc.setBoolean(selectedConfig, prefs.getBoolean(PREF_ADHOC,
                //      false));
                wcAdhoc.setBoolean(selectedConfig, false);
                int freq = 2462;    // default to channel 11
                //int freq = Integer.parseInt(prefs.getString(PREF_ADHOC_FREQUENCY,
                //"2462"));     // default to channel 11
                //System.err.println(freq);
                wcAdhocFreq.setInt(selectedConfig, freq); 
            } catch (Exception e) {
                e.printStackTrace();
                callbackContext.error(data.getString(0) + " error connection.");
                return false;
            }

        } catch (Exception e) {
            // TODO Auto-generated catch block
            // FIXME As above, what should I do here?
            e.printStackTrace();
            callbackContext.error(data.getString(0) + " error connection.");
            return false;
        }

        WifiManager wifiManag = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        boolean res1 = wifiManag.setWifiEnabled(true);
        int res = wifiManag.addNetwork(selectedConfig);
        Log.d("WifiPreference", "add Network returned " + res );
        boolean b = wifiManag.enableNetwork(selectedConfig.networkId, false);
        Log.d("WifiPreference", "enableNetwork returned " + b );
        boolean c = wifiManag.saveConfiguration();
        Log.d("WifiPreference", "Save configuration returned " + c );
        boolean d = wifiManag.enableNetwork(res, true);   
        Log.d("WifiPreference", "enableNetwork returned " + d );  

        callbackContext.success(data.getString(0) + " successfully added.");
        return true;
    }
}
