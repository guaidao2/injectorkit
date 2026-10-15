import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * A parameter that reaches `new URL(userInput).openStream()`.
 *
 * This is the shape a pseudo-protocol bug takes in Java: there is no include and
 * no file read in the application's own code, only a URL it was handed. Which
 * schemes the JVM will open for it is the whole attack surface.
 */
public class ProtoLab {

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9100;
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        // Not the default single-threaded dispatcher: one URL that hangs would
        // otherwise block every request behind it, which is exactly what a
        // remote scheme does while it waits for a host that never answers.
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(8));
        server.createContext("/fetch", ProtoLab::fetch);
        server.start();
        System.out.println("proto lab listening on " + port);
    }

    private static void fetch(HttpExchange exchange) throws java.io.IOException {
        String target = param(exchange.getRequestURI().getRawQuery(), "url");
        byte[] payload;
        try {
            URL url = new URL(target);
            java.net.URLConnection connection = url.openConnection();
            connection.setConnectTimeout(4000);
            connection.setReadTimeout(4000);
            try (InputStream in = connection.getInputStream()) {
                // Byte for byte. A class file or an archive is not text, and
                // decoding it as text destroys exactly the bytes that identify it.
                payload = in.readAllBytes();
            }
        } catch (Exception failure) {
            payload = ("fetch failed: " + failure).getBytes(StandardCharsets.UTF_8);
        }
        exchange.sendResponseHeaders(200, payload.length);
        try (OutputStream stream = exchange.getResponseBody()) {
            stream.write(payload);
        }
    }

    private static String param(String query, String name) {
        if (query == null) {
            return "";
        }
        for (String pair : query.split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0 && pair.substring(0, equals).equals(name)) {
                return java.net.URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8);
            }
        }
        return "";
    }
}
