package scheduler.auth.exception;


import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.OK)
public class TokenStillValidException extends RuntimeException{

    public TokenStillValidException(String message) {
        super(message);
    }

}
