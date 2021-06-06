# Phishing Filter Poc

This java project is a Proof of Concept for the phishing classifier implemented in PhishingFilterTool

## Getting Started

### Requirements
This program is built with Java 12. You can check your version of Java by entering the following command in a terminal window: 
```sh
java -version
```

This is a Maven project (3.8.1), so you must check Maven is installed in your local:
```sh
mvn -version
```

### Generate jar file in target folder
```sh
mvn clean package
```

### Copy dependencies in target/lib folder
```sh
mvn -DoutputDirectory=target/lib dependency:copy-dependencies 
```

### Generate csv file from email(phishing/ham) collections
```sh
java -jar AttributesExtractorPoc-1.0-SNAPSHOT.jar {email_collection_path} {model_type[GBM, Stacked]}
```


