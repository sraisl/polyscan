import java.sql.Connection;
import java.sql.Statement;

public class VulnExample {
    public void badSql(Connection conn, String userInput) throws Exception {
        // SQL Injection
        Statement st = conn.createStatement();
        st.execute("SELECT * FROM users WHERE name = '" + userInput + "'");
    }

    public void commandInjection(String filename) throws Exception {
        // Command Injection
        Runtime.getRuntime().exec("cat " + filename);
    }

    public boolean weakHash(String pwd) {
        // Weak hash (MD5)
        return pwd.hashCode() == 12345;
    }
}
