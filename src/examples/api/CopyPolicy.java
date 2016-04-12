package examples.api;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import com.ibm.itim.apps.ApplicationException;
import com.ibm.itim.apps.AuthorizationException;
import com.ibm.itim.apps.PlatformContext;
import com.ibm.itim.apps.SchemaViolationException;
import com.ibm.itim.apps.identity.OrganizationalContainerMO;
import com.ibm.itim.apps.policy.ProvisioningPolicy;
import com.ibm.itim.apps.policy.ProvisioningPolicyManager;
import com.ibm.itim.apps.provisioning.AccountManager;
import com.ibm.itim.apps.search.SearchMO;
import com.ibm.itim.apps.search.SearchResultsMO;
import com.ibm.itim.common.AttributeValue;
import com.ibm.itim.common.AttributeValues;
import com.ibm.itim.dataservices.model.CompoundDN;
import com.ibm.itim.dataservices.model.DistinguishedName;
import com.ibm.itim.dataservices.model.ObjectProfileCategory;

/**
 * Sample command-line Java class to change an account.
 */
public class CopyPolicy {
	/**
	 * Command line argument names (prefixed by "-")
	 */
	private static final String PROFILE = "profile";

	private static final String POLICY_FILTER = "policyfilter";

	private static final String FILEPATH = "filepath";

	private static final String[][] utilParams = new String[][] {
			{ PROFILE, "No profile specified" },
			{ POLICY_FILTER, "No accountfilter specified" },
			{ FILEPATH, "No filepath specified" } };

	private static String userName;

	private static String serviceName;

	private static Object complianceStr;

	public static void main(String[] args) {
		run(args, true);
	}

	/**
	 * Run the example.
	 * 
	 * @param args
	 *            Arguments passed in, usually from the command line. See usage
	 *            from more information.
	 * @param verbose
	 *            Should the program print out lots of information.
	 * @return true if run() completes successfully, false otherwise.
	 */
	@SuppressWarnings("deprecation")
	public static boolean run(String[] args, boolean verbose) {

		Utils utils = null;
		Hashtable<String, Object> arguments = null;
		PlatformContext platform = null;

		try {
			utils = new Utils(utilParams, verbose);
			arguments = utils.parseArgs(args);
		} catch (IllegalArgumentException ex) {
			if (verbose) {
				System.err.println(getUsage(ex.getMessage()));
			}
			return false;
		}
		String accountProfile = (String) arguments.get(PROFILE);
		String policyFilter = (String) arguments.get(POLICY_FILTER);
		String filePath = (String) arguments.get(FILEPATH);

		utils.print(accountProfile+": account profile \n");
		utils.print(policyFilter + ": accountFilter \n");
		utils.print(filePath + ":  filePath \n");
		File file = new File(filePath);
		if (!file.exists()) {
			try {
				file.createNewFile();
			} catch (IOException e) {
				utils.print("Error creating file +e.toString() \n");
			}
		}

		FileWriter fw = null;
		try {
			fw = new FileWriter(file.getAbsoluteFile());
		} catch (IOException e1) {
			utils.print("Error creating filewriter:" + e1.toString());
		}

		BufferedWriter print = new BufferedWriter(fw);

		try {
			String tenantId = utils.getProperty(Utils.TENANT_ID);
			String ldapServerRoot = utils.getProperty(Utils.LDAP_SERVER_ROOT);
			platform = utils.getPlatformContext();
			Subject subject = utils.getSubject();

			// platform = utils.getPlatformContext();
			// Subject subject = utils.getSubject();

			utils.print("Searching for Account \n");
			// Use the Search API to locate the Account to deprovision

			SearchMO searchMO = new SearchMO(platform, subject);
			searchMO.setCategory(ObjectProfileCategory.PROVISIONING_POLICY);

			String dn = "ou=" + tenantId + "," + ldapServerRoot;
			searchMO.setContext(new CompoundDN(new DistinguishedName(dn)));
			//searchMO.setProfileName(accountProfile);
			searchMO.setFilter(policyFilter);
			SearchResultsMO searchResultsMO = null;
			Collection<ProvisioningPolicy> policies = null;
			try {
				searchResultsMO = searchMO.execute();
				policies = searchResultsMO.getResults();
				if (policies.size() == 0) {
					utils.print("No matching account found.");
					return false;

				}
			} finally {
				utils.print(policies.size() + " found accounts to process \n");
				// close SearchResultsMO
				if (searchResultsMO != null) {
					try {
						searchResultsMO.close();
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
			AccountManager accMgr = new AccountManager(platform, subject);

			utils.print("userName;" + "serviceName;" + "complianceStatus;"
					+ "attrName;" + "attrChangeOperation;" + "oldValue;"
					+ "newValue" + "\n");

			try {
				print.write("userName;" + "serviceName;" + "complianceStatus;"
						+ "attrName;" + "attrChangeOperation;" + "oldValue;"
						+ "newValue" + "\n");
			}

			catch (IOException e1) {
				utils.print("Error writing to file: " + e1.toString());
			}

			for (Iterator<ProvisioningPolicy> iterator = policies.iterator(); iterator
					.hasNext();) {
				ProvisioningPolicy policy = iterator.next();

				Collection entNew = policy.getEntitlements();
				AttributeValues avExist = policy.getAttributes();
				AttributeValues aValues = null;
				Collection memberships = policy.getMemberships();
				String parentDnStr = avExist.get("erparent").getValueString();
				for (Iterator iterator2 = entNew.iterator(); iterator2
						.hasNext();) {
					AttributeValue attr = (AttributeValue) iterator2.next();
					AttributeValue newAV = null;
					newAV.setName(attr.getName());
					newAV.addValues(attr.getValues());
					aValues.put(newAV);
					
					System.out.println("Attr: " + attr.getName()+", value = "+attr.getValueString());
		
				}
				
			//	AttributeValues avNew = policy.getAttributes();	
				//avNew.setAttribute("","");
				//avNew.
				
//				ProvisioningPolicyManager manager = new ProvisioningPolicyManager(platform, subject);
				DistinguishedName orgDN = new DistinguishedName(parentDnStr);
				 OrganizationalContainerMO containerMO = new OrganizationalContainerMO(
			             platform, subject, orgDN);

				 com.ibm.itim.apps.policy.ProvisioningPolicy policy2 = null;

				ProvisioningPolicyManager manager = new ProvisioningPolicyManager(platform, subject);


			//	com.ibm.itim.apps.Request req = null;	
				policy2.setAttributes(aValues);
				policy2.setMemberships(memberships);
				policy2.setEntitlements(entNew);	

				com.ibm.itim.apps.Request req = null;	
				
				try {
					//		manager.createPolicy(arg0, arg1, arg2)
							 req = manager.createPolicy(containerMO, policy2, null);
						} catch (RemoteException e) {
							// TODO Auto-generated catch block
							System.out.println("goonapi /person error fetching dn: "  + " error: -" +e );
						} catch (ApplicationException e) {
							// TODO Auto-generated catch block
							System.out.println("goonapi /person error fetching dn: " + " error: -" +e );
						}	
		
					}
			// Account account = (Account) accounts.iterator().next();

			// utils.print("Request submitted. Process Id: " + request.getID());

	} catch (RemoteException e) {
			e.printStackTrace();
		} catch (LoginException e) {
			e.printStackTrace();
		} catch (SchemaViolationException e) {
			e.printStackTrace();
		} catch (AuthorizationException e) {
			e.printStackTrace();
		} catch (ApplicationException e) {
			e.printStackTrace();
		} finally {
			try {
				print.close();
			} catch (IOException e) {
				utils.print("Error closing file " + e.toString());
			}

			if (platform != null) {

				platform.close();
				platform = null;
			}
		}
		
	
		return true;
	}

	public static String getUsage(String msg) {
		StringBuffer usage = new StringBuffer();
		usage.append("\nchangeAccount: " + msg + "\n");
		usage.append("usage: changeAccount -[argument] ? \"[value]\"\n");
		usage.append("\n");
		usage.append("-profile\tObject Profile Name for the Account to change");
		usage.append(" (e.g., LDAPAccount)\n");
		usage.append("-accountfilter\tLdap Filter to search for the Account ");
		usage.append("to change\n");
		usage.append("-filepath\tOutputfile path\n");
		usage.append("\n");
		usage.append("Example: checkPolicy -profile?LDAPAccount ");
		usage.append("-accountfilter?\"(&(owner=*)(eruid=JSmith))\" ");
		usage.append("-attribute?\"filepath=/tmp/checkCompliance.log\" ");

		return usage.toString();
	}

}
