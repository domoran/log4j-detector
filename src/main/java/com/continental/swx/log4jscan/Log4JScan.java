package com.continental.swx.log4jscan;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


class ContainerState {
    private static final String FILE_LOG4J_1 = "core/LogEvent.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_2 = "core/Appender.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_3 = "core/Filter.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_4 = "core/Layout.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_5 = "core/LoggerContext.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_2_10 = "appender/nosql/NoSqlAppender.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_VULNERABLE = "JndiLookup.class".toLowerCase(Locale.ROOT);
    private static final String FILE_LOG4J_SAFE_CONDITION1 = "JndiManager.class".toLowerCase(Locale.ROOT);

    ContainerState parent; 
    
    boolean has1 = false;
    boolean has2 = false;
    boolean has3 = false;
    boolean has4 = false;
    boolean has5 = false;  
    
    boolean has10 = false; 
    boolean hasVulnerable = false; 
    boolean isSafe = false;
	private String location;
	private String type;
	private boolean isDirectoryState;
	private ArrayList<String> foundFiles = new ArrayList<String>();  
    
    public ContainerState(ContainerState parent, String location, String type) {
		this.parent = parent; 
		this.location = location;
		this.type = type; 
		
		this.isDirectoryState = this.type.equalsIgnoreCase("directory"); 
	}
    
    void foundFile(String fn) {
    	String f = fn.toLowerCase();
		if (f.contains(FILE_LOG4J_1)) { has1 = true; foundFiles.add(fn); }  
    	if (f.contains(FILE_LOG4J_2)) { has2 = true; foundFiles.add(fn); }
    	if (f.contains(FILE_LOG4J_3)) { has3 = true;  foundFiles.add(fn); }
    	if (f.contains(FILE_LOG4J_4)) { has4 = true;  foundFiles.add(fn); }
    	if (f.contains(FILE_LOG4J_5)) { has5 = true;  foundFiles.add(fn); }
    	if (f.contains(FILE_LOG4J_2_10)) { has10 = true;  foundFiles.add(fn); }
    	if (f.contains(FILE_LOG4J_VULNERABLE)) { hasVulnerable = true;  foundFiles.add(fn); }
    	if (f.contains(FILE_LOG4J_SAFE_CONDITION1)) { isSafe = true;  foundFiles.add(fn); }
    }
    
    
    ContainerState getParent() { return parent; }

	public void evaluate() {
		if (isDirectoryState) {
			if (hasVulnerable) {
				System.out.println(getLocation() + " - Vulnerable JAR found on file system");
			}
		} else {
			boolean isLog4J = has1 && has2 && has3 && has4 && has5; 
			// System.out.println("Evaluating container: " + location);	
			 StringBuilder buf = new StringBuilder();
	         if (isLog4J) {
	             buf.append(getLocation()).append("\ncontains Log4J-2.x   ");
	             if (hasVulnerable) {
	                 if (has10) {
	                     buf.append(">= 2.10.0 _VULNERABLE_ :-(");
	                 } else {
	                     buf.append(">= 2.0-beta9 (< 2.10.0) _VULNERABLE_ :-(");
	                 }
	             } else {
	                 buf.append("<= 2.0-beta8 _POTENTIALLY_SAFE_ :-| (or did you already remove JndiLookup.class?) ");
	             }
	             System.out.println(buf);
//	             System.out.println("Found files: \n" + String.join("\n# ", foundFiles) + "\n");
	         }
		}
	}

	private String getLocation() {
		return (parent == null || parent.type.equals("DIRECTORY")) ? location : (parent.getLocation() + "\n--> " + location);  
	}
}

public class Log4JScan {	
	private ContainerState currentContainer; 

	public Log4JScan() {
	}
	
	public void scan(Path path) {
		currentContainer = new ContainerState(currentContainer, path.toString(), "DIRECTORY");
		
		if (path.toFile().isDirectory()) {
			try {
				scanDirectory(path);
			} catch (IOException e) {	
				System.err.println("Could not scan directory " + path.toString() + ": " + e.getMessage());
				e.printStackTrace();
			} 
		} else {
			try {
				scanFile(path);
			} catch (IOException e) {
				System.err.println("Error scanning file: " + path.toString() + ": " + e.getMessage());
				e.printStackTrace();
			} 
		}
		
		currentContainer.evaluate();
		currentContainer = currentContainer.getParent();
		
	}

	private void scanFile(Path path) throws IOException {
		String fullName = path.toString();
		String fileName = path.getFileName().toString();
		checkName(fullName, "");
		if (isContainer(fileName)) scanZip(path);
	}

	private boolean isContainer(String fn) {
		boolean isContainer = false; 
		if (fn.endsWith(".jar")
				|| fn.endsWith(".zip")
				|| fn.endsWith(".war")
				|| fn.endsWith(".ear")
				|| fn.endsWith(".aar")
		) {
			isContainer = true; 
		}
		return isContainer;
	}

	private boolean checkName(String filePath, String prefix) {
		File file = new File(filePath); 
		currentContainer.foundFile(filePath);
		return isContainer(file.getName()); 
	}

	private void scanZip(Path path) throws IOException {
		try (
				FileInputStream fileStrm = new FileInputStream(path.toFile());
		) {
			scanZipStream(fileStrm, path.toString());
		} 
	}

	private void scanZipStream(InputStream fileStrm, String prefix) throws IOException {
		currentContainer = new ContainerState(currentContainer, prefix, "ZIP");
		try (
				BufferedInputStream bufferStrm = new BufferedInputStream(fileStrm);
				ZipInputStream zipStrm = new ZipInputStream(bufferStrm);
		) {
			do {
				ZipEntry entry = null; 
				try {
					entry = zipStrm.getNextEntry();
				} catch (IOException e) {
					break; 
				} catch (IllegalArgumentException e2) {
					System.out.println("Could not decode next entry in zip file: " + prefix);
					continue; 
				}
				if (entry == null) break;
				
				boolean isContainer = checkName(entry.getName(), prefix);
				if (isContainer) {					
					scanZipStream(zipStrm, entry.getName());
				} else {
					
				}
				
			} while (true); 
		}

		currentContainer.evaluate(); 
		currentContainer = currentContainer.getParent();
		
	}

	private void scanDirectory(Path path) throws IOException {
		Files.newDirectoryStream(path)
		.forEach(this::scan);		
	}

	public static void main(String[] args) {
		if (args.length != 1) {
			System.err.println("usage: scan <directory>");
			return;
		}
		
		new Log4JScan()
		.scan(Paths.get(args[0]));
	}
}
