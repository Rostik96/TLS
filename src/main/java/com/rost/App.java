package com.rost;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) throws IOException, InterruptedException, URISyntaxException {
        HttpClient httpClient = HttpClient.newBuilder().build();
        HttpRequest req = HttpRequest.newBuilder()
                .GET()
                .uri(new URI("https://artifactory.vsk.ru/ui/native/repo1.maven.org"))
                .build();
        System.out.println("Sending request...");
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        System.out.println("Printing body...");
        System.out.println(resp.body());
    }
}
