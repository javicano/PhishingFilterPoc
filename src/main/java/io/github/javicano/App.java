package io.github.javicano;

import io.github.javicano.phishing.filter.Features;
import io.github.javicano.phishing.filter.PhishingFilter;
import io.github.javicano.phishing.filter.PhishingFilterFactory;

/**
 * POC
 *
 */
public class App 
{
    public static void main(String[] args){
    	
    	String emailPath = "/Users/jcano/Documents/phishing-email-features-extraction/features-extractor/collections/ham/easy_ham/00001.7c53336b37003a9286aba55d2945844c";
    	
    	PhishingFilter phishingFilter = PhishingFilterFactory.getInstance();
    	//Features features = phishingFilter.getFeatures(emailPath);
    	
    	boolean result = phishingFilter.isPhishingEmail("email");
    	
    }
}
