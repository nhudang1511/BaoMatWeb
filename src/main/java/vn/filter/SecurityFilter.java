package vn.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.owasp.encoder.Encode;

public class SecurityFilter implements Filter {

	@Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Khởi tạo bộ lọc (có thể cần thiết trong một số trường hợp)
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // Lọc các tham số yêu cầu để chặn các tấn công XSS
        String content = request.getParameter("txtS");

        // Kiểm tra và chặn các mã độc XSS
        if (content != null) {
            String cleanedContent = Encode.forHtml(content);

            // Kiểm tra và chặn các mã độc script
            if (cleanedContent.contains("&lt;script") || cleanedContent.contains("&lt;/script")) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid request");
                return;
            }

            // Kiểm tra và chặn các thẻ iframe
            if (cleanedContent.contains("&lt;iframe") || cleanedContent.contains("&lt;/iframe")) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid request");
                return;
            }
        }

        // Tiếp tục xử lý yêu cầu nếu không tìm thấy mã độc XSS
        filterChain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Giải phóng tài nguyên (có thể cần thiết trong một số trường hợp)
    }
}
