/******************************************************************************
* Licensed Materials - Property of IBM
*
* (C) Copyright IBM Corp. 2007, 2012 All Rights Reserved.
*
* US Government Users Restricted Rights - Use, duplication, or
* disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
*
*****************************************************************************/

package examples.api;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import com.ibm.itim.apps.ApplicationException;
import com.ibm.itim.apps.InitialPlatformContext;
import com.ibm.itim.apps.PlatformContext;
import com.ibm.itim.common.AttributeValue;
import com.ibm.websphere.security.auth.callback.WSCallbackHandlerImpl;

public class Utils {
	public static final String TENANT_ID = "enrole.defaulttenant.id";

	public static final String LDAP_SERVER_ROOT = "enrole.ldapserver.root";

	public static final String TRUST_STORE = "javax.net.ssl.trustStore";

	public static final String TRUST_STORE_PASSWORD = "javax.net.ssl.trustStorePassword";

	public static final String TRUST_STORE_TYPE = "javax.net.ssl.trustStoreType";

	public static final String SSL_CONFIG_URL = "com.ibm.SSL.ConfigURL";

	private static final String LOGIN_CONTEXT = "WSLogin";

	private static final String ITIM_HOME = "itim.home";

	private static final String ENROLE_PROPS = "/data/enRole.properties";
	
	/**
	 * erglobalid=00000000000000000000 - The rest of the DN must be appended.
	 */
	public static final String DEFAULT_ORG_ID = "erglobalid=00000000000000000000";

	/**
	 * Should the Utils class print out messages about what it is doing?
	 */
	private boolean verbose;

	private String[][] required;

	private Properties props;

	/**
	 * Create a new Utils object to help with processing.
	 * 
	 * @param requiredParams
	 *            A 2D String Array where required[x][0] is the name of a
	 *            required parameter, and required[x][1] is the error message to
	 *            present if the parameter is missing. requiredParams must not
	 *            be null.
	 * @param isVerbose
	 *            Should the Utils class print out messages about what it is
	 *            doing? <code>true</code> if Utils should be verbose,
	 *            <code>false</code> otherwise.
	 */
	public Utils(String[][] requiredParams, boolean isVerbose) {
		if (requiredParams == null) {
			throw new IllegalArgumentException(
					"Required parameter requiredParams cannot be null.");
		}

		required = requiredParams;
		verbose = isVerbose;
	}

	/**
	 * Parses the argument list from the command-line
	 */
	public Hashtable<String, Object> parseArgs(String[] args) {
		Hashtable<String, Object> arguments = new Hashtable<String, Object>();
		String argumentList = "";
		for (int i = 0; i < args.length; i++) {
			argumentList += args[i];
		}

		StringTokenizer tokenizer = new StringTokenizer(argumentList, "-");
		while (tokenizer.hasMoreTokens()) {
			String token = (String) tokenizer.nextToken();
			int delim = token.indexOf("?");
			String name = token.substring(0, delim);
			String value = token.substring(delim + 1, token.length());
			if (arguments.get(name) != null) {
				// arg name used previous
				Object vals = arguments.get(name);
				if (vals instanceof String) {
					// convert to String[]
					Vector<String> values = new Vector<String>(2);
					values.add((String) vals);
					values.add(value);

					arguments.put(name, values);
				} else if (vals instanceof Vector) {
					// add new element to String[]
					Vector<String> values = (Vector<String>) vals;
					values.add(value);
					arguments.put(name, vals);
				}
			} else {
				arguments.put(name, value);
			}
		}

		checkArguments(arguments);
		return arguments;
	}

	/**
	 * Retrieves data from the following System properties:
	 * <ul>
	 * <li>apps.context.factory</li>
	 * <li>apps.server.url</li>
	 * </ul>
	 * 
	 * @return The platform context.
	 * @throws RemoteException
	 * @throws ApplicationException
	 */
	public PlatformContext getPlatformContext() throws RemoteException,
			ApplicationException {
		String contextFactory = getProperty("apps.context.factory");
		String appServerUrl = getProperty("enrole.appServer.url");
		
		// get the fallback itim user/password/realm to be used when the subject
		// is not supplied/required
	    String itimUser = getProperty("itim.user");
	    String itimPswd = getProperty("itim.pswd");
	    String itimRealm = getProperty("enrole.appServer.realm");

		// Setup environment table to create an InitialPlatformContext
		Hashtable<String, String> env = new Hashtable<String, String>();
		env.put(InitialPlatformContext.CONTEXT_FACTORY, contextFactory);
		env.put(PlatformContext.PLATFORM_URL, appServerUrl);
		// add fallback user/password/realm
		env.put(PlatformContext.PLATFORM_PRINCIPAL, itimUser);
		env.put(PlatformContext.PLATFORM_CREDENTIALS, itimPswd);
		env.put(PlatformContext.PLATFORM_REALM, itimRealm);

		print("Creating new PlatformContext \n");

		return new InitialPlatformContext(env);
	}

	/**
	 * Retrieves data from the following System properties and authenticates
	 * the user to WebSphere security runtime.
	 * <ul>
	 * <li>itim.user</li>
	 * <li>itim.pswd</li>
	 * <li>enrole.appServer.realm</li>
	 * </ul>
	 * 
	 * @return The authenticated user subject.
	 * @throws LoginException Thrown When the login fails.
	 */
	public Subject getSubject() throws LoginException {
		
		String itimUser = getProperty("itim.user");
		String itimPswd = getProperty("itim.pswd");
		String itimRealm = getProperty("enrole.appServer.realm");

		// Create the JAAS CallbackHandler
		CallbackHandler handler = null;
		if (itimRealm == null) {
			handler = new WSCallbackHandlerImpl(itimUser, itimPswd);
		} else {
			handler = new WSCallbackHandlerImpl(itimUser, itimRealm, itimPswd);
		}

		print("Logging in \n");
		// Associate the CallbackHandler with a LoginContext, then try to
		// authenticate the user with the platform
		LoginContext lc = new LoginContext(LOGIN_CONTEXT, handler);
		lc.login();
		Subject sub = lc.getSubject();

		print("Getting subject \n");

		// Extract the authenticated JAAS Subject from the LoginContext
		return sub;
	}
	

	/**
	 * Creates an AttributeValue from the given name=value pair.
	 * 
	 * @param nameValuePair
	 *            String in the format of string=value.
	 * @return An AttributeValue object that holds the data in nameValuePair
	 */
	public static AttributeValue createAttributeValue(String nameValuePair) {
		String name = nameValuePair.substring(0, nameValuePair.indexOf("="));
		String value = nameValuePair.substring(nameValuePair.indexOf("=") + 1,
				nameValuePair.length());
		AttributeValue attrVal = new AttributeValue(name, value);		
		return attrVal;
	}

	/**
	 * Creates an AttributeValueMap from the given Vector attributes.
	 * 
	 * @param attributes
	 *            Vector Form Commandline argument.
	 * 
	 */
	public static Map<String, AttributeValue> createAttributeValueMap(Vector attributes) {
		Iterator it = attributes.iterator();
		Map<String, AttributeValue> map=new HashMap<String, AttributeValue>();
		while (it.hasNext()) {
			String nameValuePair=(String)it.next();
			String name = nameValuePair.substring(0, nameValuePair.indexOf("="));
			String value = nameValuePair.substring(nameValuePair.indexOf("=") + 1,
				nameValuePair.length());
			
			if(!map.containsKey(name)){
				AttributeValue attrVal = new AttributeValue(name, value);		
				map.put(name,attrVal);
			}else{
				map.get(name).addValue(value);
			} 			
		}
		return map;
	}	
	
	private boolean checkArguments(Hashtable<String, Object> arguments) {
		for (int i = 0; i < required.length; i++) {
			if (!arguments.containsKey(required[i][0])) {
				throw new IllegalArgumentException(required[i][1]);
			}
		}

		return true;
	}

	public String getProperty(String propName) {
		if (props == null) {
			props = new Properties();

			String itimHome = System.getProperty(ITIM_HOME);
			try {
				props.load(new FileInputStream(itimHome + ENROLE_PROPS));
			} catch (FileNotFoundException ex) {
				throw new RuntimeException(ex);
			} catch (IOException ex) {
				throw new RuntimeException(ex);
			}
		}

		String value = System.getProperty(propName);

		if (value == null) {
			value = props.getProperty(propName);
		}

		return value;
	}

	public void print(String msg) {
		if (verbose) {
			System.out.println(msg);
		}
	}
}
