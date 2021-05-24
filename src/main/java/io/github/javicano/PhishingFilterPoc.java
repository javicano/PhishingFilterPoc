package io.github.javicano;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.james.mime4j.MimeException;

import io.github.javicano.phishing.filter.PhishingFilter;
import io.github.javicano.phishing.filter.PhishingFilterFactory;

/**
 * PhishingFilterPoc
 *
 */
public class PhishingFilterPoc {
	
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
	
	private static void inboxClassifier(File[] emails) {
    	List<EmailInfo> phishingMails = new ArrayList<EmailInfo>(); 
    	List<EmailInfo> hamMails = new ArrayList<EmailInfo>();
    	
    	PhishingFilter phishingFilter = PhishingFilterFactory.getInstance();
    	
    	for(File email: emails) {
    		boolean isPhishing;
			try {
				isPhishing = phishingFilter.isPhishingEmail(email);
				EmailInfo emailInfo = getEmailInfo(email);
				if(isPhishing == true) {
	    			phishingMails.add(emailInfo);
	    		}
	    		else {
	    			hamMails.add(emailInfo);
	    		}
			} catch (StackOverflowError | MimeException | IOException e) {
				e.printStackTrace();
			} 
    	}
    	printInbox(hamMails, phishingMails);
	}
	
	private static File[] readIncomingEmails(String colllectionPath) {
		File folder = new File(colllectionPath);
		return folder.listFiles();
	}
	
    public static void main(String[] args){
    	
    	if(args.length == 0) {
    		System.out.println("[WARN] Email collection path should be introduced");
    	} else {
    		File[] incomingEmails = readIncomingEmails(args[0]);
    		inboxClassifier(incomingEmails);
    	}	
    }
}
