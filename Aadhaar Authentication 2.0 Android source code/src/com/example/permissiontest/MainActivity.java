package com.example.permissiontest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URI;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Locale;
import java.util.TimeZone;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.hardware.usb.UsbDevice;
import java.util.Iterator;

import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.aadhaar.auth.AESCipher;
import com.aadhaar.auth.Encrypter;
import com.aadhaar.auth.SessionKeyDetails;
import com.aadhaar.auth.UidaiAuthHelper;

import com.aadhaar.auth.XmlSigner;
import com.aadhaar.auth.XmlUtility;
import com.aadhaar.auth.UidaiAuthHelper.HashGenerator;
import com.aadhaar.auth.UidaiAuthHelper.SynchronizedKey;
import com.aadhar.commonapi.HelperInterface;
import com.bioenable.*;

import com.bioenable.andriodwrapper.BioEnableWrapper;

import android.os.AsyncTask;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcelable;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.Service;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.AssetManager;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.TextureView;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.StringWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.example.permissiontest.MainActivity;
import com.nitgen.SDK.AndroidBSP.NBioBSPJNI;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

public class MainActivity extends Activity implements HelperInterface {

	BioEnableWrapper bio;
	HelperInterface hp1 = null;
	private byte[] array1 = null;

	private byte[] array2 = null;

	String pidTimeStamp;
	String authXML;
	String signedauthXML;
	TextView msg;
	ImageView fingerImg;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		String test;
		msg = (TextView) findViewById(R.id.textViewMessage);
		fingerImg=(ImageView)findViewById(R.id.imageViewFingerPrint);

		try {
			hp1 = MainActivity.this;
			bio = new BioEnableWrapper(hp1);
			bio.InitDevice(255);

		} catch (Exception e) {
			Toast.makeText(getApplicationContext(), "Exc : " + e, 2000).show();
		}

	}

	public void capture1(View v) {
		/*
		 * String test; try{ hp1 = MainActivity.this; bio= new
		 * BioEnableWrapper(hp1); bio.InitDevice(255); test=bio.GetDeviceMake();
		 * // test = bio.GetVersion(); Toast.makeText(getApplicationContext(),
		 * "Msg : "+test, 2000).show();
		 * 
		 * }catch(Exception e) { Toast.makeText(getApplicationContext(),
		 * "Exc : "+e, 2000).show(); }
		 */

		bio.BeginCapture();
		String t = bio.plain_pid_xml;

		//showInfoDialog("Plain Pid Xml : " + t);

		// Toast.makeText(getApplicationContext(), "capture1 ", 2000).show();

	}

	public void capture2(View v) {
		// Toast.makeText(getApplicationContext(), "Test", 2000).show();
		bio.BeginCapture1();
		// Toast.makeText(getApplicationContext(), "capture2 ", 2000).show();
	}

	public void verify(View v) {
		if (array1 != null && array2 != null) {
			boolean result1 = bio.verify(array1, array2);

			if (result1) {
				Toast.makeText(getApplicationContext(),
						"Fingers matched Successed", 2000).show();
			} else {
				Toast.makeText(getApplicationContext(),
						"Fingers matched Failed", 2000).show();
			}
		} else {

		}
	}

	@Override
	public void handlerFunction(final byte[] rawImage, final int imageHeight,
			final int imageWidth, final int status, final String errorMessage,
			final boolean complete, final byte[] isoData, final int quality,
			final int finalNFIQ) {
		
		
		
				
		/*fingerImg.setImageBitmap(Bitmap.createScaledBitmap(bmp, imageWidth,
				imageHeight, false));
		*/
		
		
		runOnUiThread(new Runnable() {
			@Override
			public void run() {

				if (array1 == null) {
					array1 = isoData;

					String t = bio.plain_pid_xml;

					try{

					fingerImg.setImageBitmap(RawToBitmap(rawImage, imageWidth, imageHeight));
					
					}
					catch(Exception e)
					{
						Toast.makeText(getApplicationContext(), "Exe : "+e, Toast.LENGTH_LONG).show();
					}

					String demo = PerformAuthentication();

					AsyncPost post = new AsyncPost();
					post.execute();
					
				} else {
					array2 = isoData;
					Toast.makeText(getApplicationContext(),
							"Second Finger Captured", 2000).show();
					
				}

				// TODO Auto-generated method stub

			}
		});
	}

	private Bitmap RawToBitmap(byte[] rawImage, int imageWidth, int imageHeight) {

		byte[] Bits = new byte[rawImage.length * 4];

		int j;
		for (j = 0; j < rawImage.length; j++) {
			Bits[j * 4] = (byte) (rawImage[j]);
			Bits[j * 4 + 1] = (byte) (rawImage[j]);
			Bits[j * 4 + 2] = (byte) (rawImage[j]);
			Bits[j * 4 + 3] = -1;
		}
		Bitmap mCurrentBitmap = Bitmap.createBitmap(imageWidth, imageHeight,
				Bitmap.Config.ARGB_8888);
		mCurrentBitmap.copyPixelsFromBuffer(ByteBuffer.wrap(Bits));
		return mCurrentBitmap;
	}
	
	private class AsyncPost extends AsyncTask<String, Void, String> {
		@Override
		protected String doInBackground(String... params) {
			String res = "";

			String auaURL = "http://206.222.26.82:9955/";
			System.out.println("Start sending  request");
			URL url;
			try {
				url = new URL(auaURL);

				HttpURLConnection rc = (HttpURLConnection) url.openConnection();
				// System.out.println("Connection opened " + rc );
				rc.setRequestMethod("POST");
				rc.setDoOutput(true);
				rc.setDoInput(true);
				rc.setRequestProperty("Content-Type", "text/xml; charset=utf-8");

				String reqStr = authXML; // the entire payload in a single
											// String
				int len = reqStr.length();
				rc.setRequestProperty("Content-Length", Integer.toString(len));
				rc.connect();
				OutputStreamWriter out = new OutputStreamWriter(
						rc.getOutputStream());
				out.write(reqStr, 0, len);
				out.flush();
				System.out.println("Request sent, reading response ");
				InputStreamReader read = new InputStreamReader(
						rc.getInputStream());
				StringBuilder sb = new StringBuilder();
				int ch = read.read();
				while (ch != -1) {
					sb.append((char) ch);
					ch = read.read();
				}
				String response = sb.toString(); // entire response ends up in
													// String
				res = response;
				System.out.println("eading response " + response);
				read.close();
				rc.disconnect();

			} catch (MalformedURLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ProtocolException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return res;
		}

		@Override
		protected void onPostExecute(String result) {
			//showInfoDialog("REsponse from ccs server" + result);

			signedauthXML = result;

			AsyncPost1 asc1 = new AsyncPost1();
			asc1.execute();

		}

		@Override
		protected void onPreExecute() {
		}

		@Override
		protected void onProgressUpdate(Void... values) {

		}
	}

	private class AsyncPost1 extends AsyncTask<String, Void, String> {
		@Override
		protected String doInBackground(String... params) {
			String res = "";
			String Result="";

			String auaURL = "http://developer.uidai.gov.in/uidauthserver/public/9/9/MH4hSkrev2h_Feu0lBRC8NI-iqzT299_qPSSstOFbNFTwWrie29ThDo";
			System.out.println("Start sending  request");
			URL url;
			try {
				url = new URL(auaURL);

				HttpURLConnection rc = (HttpURLConnection) url.openConnection();
				// System.out.println("Connection opened " + rc );
				rc.setRequestMethod("POST");
				rc.setDoOutput(true);
				rc.setDoInput(true);
				rc.setRequestProperty("Content-Type", "text/xml; charset=utf-8");

				String reqStr = signedauthXML; // the entire payload in a single
												// String
				int len = reqStr.length();
				rc.setRequestProperty("Content-Length", Integer.toString(len));
				rc.connect();
				OutputStreamWriter out = new OutputStreamWriter(
						rc.getOutputStream());
				out.write(reqStr, 0, len);
				out.flush();
				System.out.println("Request sent, reading response ");
				InputStreamReader read = new InputStreamReader(
						rc.getInputStream());
				StringBuilder sb = new StringBuilder();
				int ch = read.read();
				while (ch != -1) {
					sb.append((char) ch);
					ch = read.read();
				}
				String response = sb.toString(); // entire response ends up in
													// String
				res = response;
				
			
				// Add Code for xml parse 
				
				if(res.contains("ret=\"y\""))
				{
					Result="Authentication successful";
				}
				else
				{
					Result="Authentication failed";
				}
				
				
				
				System.out.println("eading response " + response);
				read.close();
				rc.disconnect();

			} catch (MalformedURLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ProtocolException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			//return res;
			return Result;
		}

		@Override
		protected void onPostExecute(String result) {
			//showInfoDialog("REsponse from UIDAI" + result);

			showInfoDialog("UIDAI " + result);
			
			
		}

		@Override
		protected void onPreExecute() {
		}

		@Override
		protected void onProgressUpdate(Void... values) {

		}
	}

	private String PerformAuthentication() {

		// String stringIsoData = Base64.encodeToString(array1,Base64.DEFAULT);
		// String pidxml = bio.get_PID_xml("xyz", true, false, stringIsoData,
		// "FMR");
		// showInfoDialog("My PID XML : "+pidxml);

		byte[] encryptedSessionKey;

		// byte[] xmlPidBytes = pidxml.getBytes();
		// AESCipher aesCipher = new AESCipher();
		// byte[] inputData = pidxml.getBytes();
		try {

			DocumentBuilderFactory docFactory = DocumentBuilderFactory
					.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
			// root elements
			Document doc = docBuilder.newDocument();
			Element rootElement = doc.createElement("Auth");
			doc.appendChild(rootElement);
			Attr attr = null;
			addXmlElementAttribute("uid", "999922331279", doc, rootElement);
			addXmlElementAttribute("tid", "registered", doc, rootElement);
			addXmlElementAttribute("sa", "public", doc, rootElement);
			addXmlElementAttribute("ver", "2.0", doc, rootElement);
			addXmlElementAttribute("txn", "uidai", doc, rootElement);
			addXmlElementAttribute("rc", "Y", doc, rootElement);
			addXmlElementAttribute("ac", "public", doc, rootElement);
			addXmlElementAttribute("lk",
					"MP7Pw-BXZb75p5k6oJQyz73EWXd--yNuZV7lnYtNl7ZQF-hZFiTZ2vk",
					doc, rootElement);
			addXmlElementAttribute(
					"xmlns",
					"http://www.uidai.gov.in/authentication/uid-auth-request/1.0",
					doc, rootElement);
			Element uses = doc.createElement("Uses");
			rootElement.appendChild(uses);
			addXmlElementAttribute("otp", "n", doc, uses);
			addXmlElementAttribute("pin", "n", doc, uses);
			addXmlElementAttribute("pfa", "n", doc, uses);
			addXmlElementAttribute("pa", "n", doc, uses);
			if (false) {
				addXmlElementAttribute("pi", "y", doc, uses);
			} else {
				addXmlElementAttribute("pi", "n", doc, uses);
			}
			if (true) {
				addXmlElementAttribute("bio", "y", doc, uses);
				addXmlElementAttribute("bt", "FMR", doc, uses);
			} else {
				addXmlElementAttribute("bio", "n", doc, uses);
			}
			Element meta = doc.createElement("Meta");
			rootElement.appendChild(meta);
			addXmlElementAttribute("udc", "BIOE0", doc, meta);
			addXmlElementAttribute("fdc", "NC", doc, meta);
			addXmlElementAttribute("idc", "NA", doc, meta);

			addXmlElementAttribute("fpmi", "103", doc, meta);
			addXmlElementAttribute("irmi", "NA", doc, meta);
			addXmlElementAttribute("fdmi", "NA", doc, meta);
			addXmlElementAttribute("fpmc", bio.get_fpmc(), doc, meta);
			addXmlElementAttribute("irmc", "NA", doc, meta);
			addXmlElementAttribute("fdmc", "NA", doc, meta);
			addXmlElementAttribute("cdc", "NA", doc, meta);
			Element skey = doc.createElement("Skey");
			rootElement.appendChild(skey);

			byte[] publicKey = null;
			String jhkPubKey = "MIIDBjCCAe6gAwIBAgIEATMzfzANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJJTjEOMAwGA1UEChMFVUlEQUkxHDAaBgNVBAMTE0F1dGhTdGFnaW5nMTYwOTIwMjAwHhcNMTUwOTE2MDAwMDAwWhcNMjAwOTE2MDAwMDAwWjA7MQswCQYDVQQGEwJJTjEOMAwGA1UEChMFVUlEQUkxHDAaBgNVBAMTE0F1dGhTdGFnaW5nMTYwOTIwMjAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGBWEdlnBNuIExu7rM/Ok1F9WnuV25tm+o+4pZPvtSFHylRSIFbt/X0/47HoSvoroX+GgxbPPaTyB5USoWhFtVRVN/HGjEGSKxDzZYKlsbQqQ80bJn2L/noCyWr9vB9JvIfqt+kCouMW70FfDhb5JjXNMoiOTEKNOHgVuqDOkWQZWVXcCX3w4OuVLu67Jf6p6qO8NncdD4zN6Ots2fpNBEEtpqoJWWRLOvN6NfISpqqWLBU5Wo0jdg917syOXinrIYn1PlnhIZdJBdc/njaRvFuVxaf6KdC8SYsKzedrzjUp+UVGcVwzDbs0MfUpAvwhlkHK7nooToE4iJ1yqgUXZpAgMBAAGjEjAQMA4GA1UdDwEB/wQEAwIFoDANBgkqhkiG9w0BAQUFAAOCAQEAT3l/ShgP46+Ctqrp/WIzheslpxvsSWpD2jwWvinXujXY6Vsc77gPQUsQawKNY0p4h9j8MDSNb8oYY8i7NxxH6kPuIjzoRNJtA1jiKANdFNuEPK9h4wETBlEfgU0yOdWer7inQO3S6pH8eGChhOHxmIqBGIfnjoWq8RbIdRrj4E/xkvvZpVj2Vp1MPyQoVJSQ+tZIAwLHtzcs7UUJUoGyII8egKDX1NFdvRM62wzfCyx5J1wSSaCZ2V/lr7CmTmHcbC04K3BNN5Yby7FxmU5NNrTvW1ZPLVXpvo9hBfnRc+L75PPpoBV9V54wSzsn0rDKjYcpniYTcpm09Ae8SAS0vg==";
			publicKey = Base64.decode(jhkPubKey, Base64.DEFAULT);

			UidaiAuthHelper helper = new UidaiAuthHelper(publicKey);
			encryptedSessionKey = helper.encrypter.encryptUsingPublicKey(bio
					.get_encrypted_session_key());

			addXmlElementAttribute("ci",
					helper.encrypter.getCertificateIdentifier(), doc, skey);

			skey.appendChild(doc.createTextNode(Base64.encodeToString(
					encryptedSessionKey, Base64.DEFAULT)));
			Element data = doc.createElement("Data");
			attr = doc.createAttribute("type");
			attr.setValue("X");
			data.setAttributeNode(attr);
			data.appendChild(doc.createTextNode(Base64.encodeToString(
					bio.get_encrypted_PID_Block(), Base64.DEFAULT)));
			rootElement.appendChild(data);
			Element mac = doc.createElement("Hmac");
			mac.appendChild(doc.createTextNode(Base64.encodeToString(
					bio.get_PID_HMAC(), Base64.DEFAULT)));
			rootElement.appendChild(mac);

			TransformerFactory transformerFactory = TransformerFactory
					.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			DOMSource source = new DOMSource(doc);

			StringWriter writer = new StringWriter();
			StreamResult result = new StreamResult(writer);
			transformer.transform(source, result);
			String output = writer.getBuffer().toString()
					.replaceAll("\n|\r", "");

			authXML = output;

		} catch (NoSuchAlgorithmException e) {
			// showInfoDialog("NoSuchAlgorithmException" + e.getMessage());
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			// showInfoDialog("NoSuchProviderException" + e.getMessage());
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// showInfoDialog("UnsupportedEncodingException" + e.getMessage());
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// showInfoDialog("IllegalStateException" + e.getMessage());
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// showInfoDialog("Exception" + e.getMessage());
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return authXML;

		// authXML=bio.generateAuthXml(pidxml);

	}

	private void addXmlElementAttribute(String attributeName,
			String attributeValue, Document doc, Element rootElement) {
		Attr attr = doc.createAttribute(attributeName);
		attr.setValue(attributeValue);
		rootElement.setAttributeNode(attr);
	}

	public String getXMLAttribute(String inxml, String attribute) {
		XmlUtility utility = new XmlUtility();
		return utility.getNodeAttribute(inxml, attribute);
	}

	// for PID XML
	/*
	 * public String getPidXml(String uname, boolean bio, boolean pi, String
	 * isotemplate, String bioType) { String str;
	 * 
	 * DateFormat dfm = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"); long now =
	 * System.currentTimeMillis(); Date date = new Date(now); Calendar
	 * localCalendar = GregorianCalendar.getInstance();
	 * localCalendar.setTime(date); pidTimeStamp =
	 * String.valueOf(localCalendar.get(Calendar.YEAR)) + "-" +
	 * (String.valueOf(localCalendar.get(Calendar.MONTH) + 1) .length() < 2 ?
	 * "0" + String.valueOf(localCalendar.get(Calendar.MONTH) + 1) :
	 * String.valueOf(localCalendar.get(Calendar.MONTH) + 1)) + "-" +
	 * (String.valueOf(localCalendar.get(Calendar.DATE)).length() < 2 ? "0" +
	 * String.valueOf(localCalendar.get(Calendar.DATE)) :
	 * String.valueOf(localCalendar.get(Calendar.DATE))) + "T" +
	 * (String.valueOf(localCalendar.get(Calendar.HOUR_OF_DAY)) .length() < 2 ?
	 * "0" + String.valueOf(localCalendar .get(Calendar.HOUR_OF_DAY)) : String
	 * .valueOf(localCalendar.get(Calendar.HOUR_OF_DAY))) + ":" +
	 * (String.valueOf(localCalendar.get(Calendar.MINUTE)).length() < 2 ? "0" +
	 * String.valueOf(localCalendar.get(Calendar.MINUTE)) :
	 * String.valueOf(localCalendar.get(Calendar.MINUTE))) + ":" +
	 * (String.valueOf(localCalendar.get(Calendar.SECOND)).length() < 2 ? "0" +
	 * String.valueOf(localCalendar.get(Calendar.SECOND)) :
	 * String.valueOf(localCalendar.get(Calendar.SECOND)));
	 * System.out.println("PID TIME STAMP:" + pidTimeStamp); String ctime =
	 * dfm.format(date).replace(" ", "T");
	 * 
	 * 
	 * try {
	 * 
	 * DocumentBuilderFactory docFactory = DocumentBuilderFactory
	 * .newInstance(); DocumentBuilder docBuilder =
	 * docFactory.newDocumentBuilder();
	 * 
	 * // root elements Document doc = docBuilder.newDocument();
	 * 
	 * Element rootElement = doc.createElement("Pid");
	 * doc.appendChild(rootElement);
	 * 
	 * Attr attr = doc.createAttribute("ts"); attr.setValue(ctime);
	 * rootElement.setAttributeNode(attr);
	 * 
	 * attr = doc.createAttribute("ver"); attr.setValue("2.0");
	 * rootElement.setAttributeNode(attr);
	 * 
	 * attr = doc.createAttribute("xmlns"); attr.setValue(
	 * "http://www.uidai.gov.in/authentication/uid-auth-request-data/1.0");
	 * rootElement.setAttributeNode(attr);
	 * 
	 * 
	 * 
	 * // bio Start
	 * 
	 * String fpdata = isotemplate;
	 * 
	 * MessageDigest digest;
	 * 
	 * digest = MessageDigest.getInstance("SHA-256"); byte[] hash =
	 * digest.digest(fpdata.getBytes(StandardCharsets.UTF_8)); //bh
	 * 
	 * byte[] ts1 = null; long today = System.currentTimeMillis(); DateFormat
	 * sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss",Locale.getDefault());
	 * sdf.setTimeZone(TimeZone.getTimeZone("Asia/Kolkata")); String
	 * timestamp=sdf.format(new Date(today)); ts1 =
	 * timestamp.getBytes(StandardCharsets.UTF_8);
	 * 
	 * byte[] devicecode = null; showInfoDialog("Device code"); devicecode =
	 * "NC".getBytes(StandardCharsets.UTF_8);
	 * showInfoDialog("Device code ended");
	 * 
	 * 
	 * showInfoDialog("bs started");
	 * 
	 * byte[] rv = new byte[hash.length + ts1.length + devicecode.length];
	 * System.arraycopy(hash, 0, rv, 0, hash.length); System.arraycopy(ts1, 0,
	 * rv, hash.length, ts1.length); System.arraycopy(devicecode, 0, rv,
	 * hash.length + ts1.length, devicecode.length);
	 * 
	 * showInfoDialog("bs ended"+"hashlenght :"+hash.length+" ts length : "+ts1.
	 * length+" devicecode : "+devicecode.length+"bs length : "+rv.length);
	 * 
	 * // final String publicKeyPath =
	 * "//assets//certificate//bioenable_device.p12";
	 * 
	 * URL url =
	 * getClass().getResource("/assets/certificate/bioenable_device.p12");
	 * 
	 * byte[] message1 = rv; char[] pass = "bio".toCharArray();
	 * 
	 * // final String publicKeyPath =
	 * "/storage/emulated/0/bioenable_device.p12"; final String publicKeyPath
	 * ="/storage/sdcard0/bioenable_device.p12"; String jhkPubKey =
	 * "MIIDvjCCAqagAwIBAgIEWH97pjANBgkqhkiG9w0BAQsFADCBlzESMBAGA1UEAxMJQmlvZW5hYmxlMRIwEAYDVQQLEwlCaW9lbmFibGUxEjAQBgNVBAoTCUJpb2VuYWJsZTENMAsGA1UEBxMEUHVuZTEUMBIGA1UECBMLTWFoYXJhc2h0cmExCzAJBgNVBAYTAklOMScwJQYJKoZIhvcNAQkBFhhrdXNoYWxAYmlvZW5hYmxldGVjaC5jb20wHhcNMTcwMTE4MTQzMDA2WhcNMTgwMTE4MTQzMDA2WjCBlzEnMCUGCSqGSIb3DQEJARYYa3VzaGFsQGJpb2VuYWJsZXRlY2guY29tMQswCQYDVQQGEwJJTjEUMBIGA1UECAwLTWFoYXJhc2h0cmExDTALBgNVBAcMBFB1bmUxEjAQBgNVBAoMCUJpb2VuYWJsZTESMBAGA1UECwwJQmlvRU5hYmxlMRIwEAYDVQQDDAlCaW9FbmFibGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDT0gNOoVVT850AzB87jKG/6MbdlCQQCxNxEgOGR2I89mqyU7dxOJ6/ZBjEQybbz8NEe2fdbz8QgkvpQTcYSokYr2RokvT28ZBNb46dKK4y1Gn/br/rocWXC2z8u20dlPXDbtInh8zEYgMK6LYQGg1JRz+x5BlH06xoeIOrUz+QX1BPmPePM+WemnRbMkjgU8vMi/yZVV60pHXO28cXogV7zl8UdoZ9nIQSpEVQE5A3lT//ydSk721Eit0tQUbIVIHlc9J814agtkJOfiCWbGsFapJGjdA/uMnZV0hjZmf4Aju4LI/QCICSj98YVcHMKhR01nfN+Gd1C6NtB0TXIDn1AgMBAAGjEDAOMAwGA1UdDwQFAwMHhYAwDQYJKoZIhvcNAQELBQADggEBAEAFhKZoWvphKqUEAmDzP9ZfqOJUyUsjsjcc522M45yUI6wkq3nCtuxIPhg0XMtkMF3qqGe8UQZEsD96NTWjl1UfBI2RzePeYy19M2yc1chxwvitk7256yCuWt064u4uG0QAq3a+Nto/3z4cFCmRFFWNvY21Ll6cJs1iX0qMKhLsOJD+i8ULkLmiwgNVOoMAjRmoA5F7SUgc0Gpwl/wN3dJKHbW+l4BCXxN34atYkfjosxHlOpNhHKkDf9I4E9TWrRpqg2SeVstPjwMBoeGnCj1ZaecaVdcJmY4ZrBZ3aGw4JzDF4E1+AVJ22eJ01CJ5r36FOKFM2Zc8SaZFKJR2JkA="
	 * ; byte [] inpubkey = Base64.decode(jhkPubKey, Base64.DEFAULT);
	 * 
	 * CertificateFactory certFactory = CertificateFactory.getInstance("X.509",
	 * "BC"); //fileInputStream = new FileInputStream(new
	 * File(publicKeyFileName)); ByteArrayInputStream is = new
	 * ByteArrayInputStream(inpubkey); X509Certificate cert = (X509Certificate)
	 * certFactory.generateCertificate(is); is.close(); PublicKey publicKey =
	 * cert.getPublicKey(); java.util.Date certExpiryDate = cert.getNotAfter();
	 * KeyStore ks = KeyStore.getInstance("PKCS12"); FileInputStream
	 * keyFileStream = new FileInputStream(new File(publicKeyPath));
	 * ks.load(keyFileStream, "bio".toCharArray()); KeyStore.PrivateKeyEntry
	 * entry = (KeyStore.PrivateKeyEntry) ks.getEntry("bioenable_device", new
	 * KeyStore.PasswordProtection( "bio".toCharArray())); PrivateKey pk1 =
	 * entry.getPrivateKey(); Cipher cipher1 = Cipher.getInstance("RSA");
	 * cipher1.init(Cipher.ENCRYPT_MODE, pk1); byte[] dpk11 =null; dpk11 =
	 * cipher1.doFinal(message1); String base64Encoded =
	 * Base64.encodeToString(dpk11,Base64.NO_WRAP);
	 * 
	 * Element bios = doc.createElement("Bios"); rootElement.appendChild(bios);
	 * Element bioElement = doc.createElement("Bio");
	 * 
	 * attr = doc.createAttribute("type"); attr.setValue(bioType);
	 * bioElement.setAttributeNode(attr);
	 * 
	 * attr = doc.createAttribute("bs"); attr.setValue(base64Encoded);
	 * bioElement.setAttributeNode(attr);
	 * 
	 * attr = doc.createAttribute("posh"); attr.setValue("LEFT_INDEX");
	 * bioElement.setAttributeNode(attr);
	 * 
	 * bioElement.appendChild(doc.createTextNode(isotemplate));
	 * 
	 * bios.appendChild(bioElement);
	 * 
	 * // Bio End
	 * 
	 * // write the content into xml file TransformerFactory transformerFactory
	 * = TransformerFactory .newInstance(); Transformer transformer =
	 * transformerFactory.newTransformer(); DOMSource source = new
	 * DOMSource(doc);
	 * 
	 * StringWriter writer = new StringWriter(); StreamResult result = new
	 * StreamResult(writer);
	 * 
	 * transformer.transform(source, result); String output =
	 * writer.getBuffer().toString() .replaceAll("\n|\r", ""); str=output; }
	 * catch (Exception ex) { System.out.println("Error:" + ex.getMessage());
	 * str=ex.getMessage(); } return str;
	 * 
	 * }
	 */

	public void showInfoDialog(String message) {

		AlertDialog.Builder dlgAlert = new AlertDialog.Builder(
				MainActivity.this);
		dlgAlert.setMessage(message);
		dlgAlert.setTitle("Information");
		dlgAlert.setPositiveButton("OK", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {
				return;
			}
		});
		dlgAlert.setCancelable(false);
		dlgAlert.create().show();

	}

}
