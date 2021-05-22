package io.github.javicano;

import java.io.File;

import org.apache.james.mime4j.MimeException;

import io.github.javicano.phishing.filter.PhishingFilter;
import io.github.javicano.phishing.filter.PhishingFilterFactory;

/**
 * PhishingFilterPoc
 *
 */
public class PhishingFilterPoc 
{
    public static void main(String[] args){
    	
    	String hamEmailPath = "/Users/jcano/Documents/phishing-email-features-extraction/features-extractor/collections/ham/easy_ham/00001.7c53336b37003a9286aba55d2945844c";
    	String phishingEmailPath = "/Users/jcano/Documents/phishing-email-detection/AttributesExtractorPoc/collections/phishing/2018/phishing-2018-8.txt";
    	
    	File hamEmail = new File(hamEmailPath);
    	File phishingEmail = new File(phishingEmailPath);
    	
    	PhishingFilter phishingFilter = PhishingFilterFactory.getInstance();
    	try {
    		System.out.println(hamEmail.getName());
			phishingFilter.isPhishingEmail(hamEmail);
			System.out.println("");
			System.out.println(phishingEmail.getName());
			phishingFilter.isPhishingEmail(phishingEmail);
		} catch (StackOverflowError | MimeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    }
}
