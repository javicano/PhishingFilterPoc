package io.github.javicano;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.github.javicano.phishing.filter.PhishingFilter;
import io.github.javicano.phishing.filter.PhishingFilterFactory;
import io.github.javicano.phishing.filter.PhishingPrediction;

/**
 * PhishingFilterPoc
 *
 */
public class PhishingFilterPoc {
	
	private final static String GBM_TYPE = "GBM";
	
	private final static String STACKED_TYPE = "Stacked";
	
	private static void printInbox(List<EmailInfo> hamMails, List<EmailInfo> phishingMails) {
		System.out.println(" -------------------------------------------------------------");
		System.out.println(" ----                    HAM INBOX                        ----");
		System.out.println(" -------------------------------------------------------------");
		
		for(EmailInfo hamMail: hamMails) {
			System.out.println("  > " + hamMail.getFrom());
			System.out.println("    " + hamMail.getSubject());
			System.out.println("    " + hamMail.getFileName());
		}
		
		System.out.println(" ");
		System.out.println(" ");
		
		System.out.println(" -------------------------------------------------------------");
		System.out.println(" ----                  PHISHING INBOX                     ----");
		System.out.println(" -------------------------------------------------------------");
		
		for(EmailInfo phishingMail: phishingMails) {
			System.out.println("  > " + phishingMail.getFrom());
			System.out.println("    " + phishingMail.getSubject());
			System.out.println("    " + phishingMail.getFileName());
		}
	}
	
	private static EmailInfo getEmailInfo(File email) throws IOException {
		EmailInfo emailInfo = new EmailInfo();
		String emailStr = new String(Files.readAllBytes(Paths.get(email.getPath())));
		Pattern fromPattern = Pattern.compile("^(From:).*", Pattern.MULTILINE);
		Matcher fromMatcher = fromPattern.matcher(emailStr);
		if(fromMatcher.find()) {
			emailInfo.setFrom(fromMatcher.group());
		}
		Pattern subjectPattern = Pattern.compile("^(Subject:).*", Pattern.MULTILINE);
		Matcher subjectMatcher = subjectPattern.matcher(emailStr);
		if(subjectMatcher.find()) {
			emailInfo.setSubject(subjectMatcher.group());
		}
		emailInfo.setFileName(email.getName());
		return emailInfo;
	}
	
	private static void inboxClassifier(File[] emails, String modelType) {
    	List<EmailInfo> phishingMails = new ArrayList<EmailInfo>(); 
    	List<EmailInfo> hamMails = new ArrayList<EmailInfo>();
    	
    	PhishingFilter phishingFilter = PhishingFilterFactory.getInstance();
    	
    	for(File email: emails) {
    		PhishingPrediction phishiPrediction;
			try {
				phishiPrediction = phishingFilter.isPhishingEmail_GBM(email);
				EmailInfo emailInfo = getEmailInfo(email);
				if(phishiPrediction.isPhishing() == true) {
	    			phishingMails.add(emailInfo);
	    		}
	    		else {
	    			hamMails.add(emailInfo);
	    		}
			} catch (StackOverflowError | Exception e) {
				e.printStackTrace();
			} 
    	}
    	System.out.println(" ");
    	printInbox(hamMails, phishingMails);
	}
	
	private static File[] readIncomingEmails(String colllectionPath) {
		File folder = new File(colllectionPath);
		return folder.listFiles();
	}
	
    public static void main(String[] args){
    	
    	if(args.length != 2) {
			System.out.println("[ERROR] Incorrect arguments ");
			System.out.println("[INFO]  PhishingFilterPoc: ");
			System.out.println("[INFO]   - arg1: Email collection path");
			System.out.println("[INFO]   - arg2: Model type: [Stacked, GBM] ");
    	} else if (!args[1].equalsIgnoreCase(GBM_TYPE) &&  !args[1].equalsIgnoreCase(STACKED_TYPE)){
    		System.out.println("[ERROR] Incorrect Model type [Stacked, GBM]");
    	} else {
    		File[] incomingEmails = readIncomingEmails(args[0]);
    		System.out.println("Classifying incoming emails ...");
    		inboxClassifier(incomingEmails, args[1]);
    	}	
    }
}
