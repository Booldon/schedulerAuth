package scheduler.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Entity
@Getter
@Setter
public class RefreshToken {

    @Id
    @Column(unique = true, nullable = false)
    private String username;

    @Column(unique = true)
    private String randomKey;

    private Date limitTime;

    private String role;

    public void setLimitTime() {
        this.limitTime = new Date(System.currentTimeMillis() + 60*60*1000*24);
    }

    public Boolean validateRamdomKey(String randomKey) {

        if(this.randomKey.equals(randomKey)) {
            return true;
        }
        else {
            return false;
        }
    }
}
