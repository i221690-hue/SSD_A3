package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {
    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // Get balance for a specific account - only owner or admin allowed
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        Optional<Account> oa = accounts.findById(id);
        if (oa.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        Account a = oa.get();
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "").orElse(null);
        if (me == null) return ResponseEntity.status(401).build();
        if (!me.isAdmin() && !me.getId().equals(a.getOwnerUserId())) {
            Map<String,String> err = new HashMap<>();
            err.put("error","forbidden");
            return ResponseEntity.status(403).body(err);
        }
        Map<String,Object> res = new HashMap<>();
        res.put("iban", a.getIban());
        res.put("balance", a.getBalance());
        return ResponseEntity.ok(res);
    }

    // Transfer from one account to another - validate amounts and ownership
    record TransferReq(@Min(0) double amount, Long fromAccountId, Long toAccountId) {}

    @PostMapping("/transfer")
    public ResponseEntity<?> transfer(@Valid @RequestBody TransferReq req, Authentication auth) {
        if (req.amount() <= 0 || req.amount() > 1000000) {
            Map<String,String> err = new HashMap<>();
            err.put("error","invalid amount");
            return ResponseEntity.badRequest().body(err);
        }
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "").orElse(null);
        if (me == null) return ResponseEntity.status(401).build();

        Account from = accounts.findById(req.fromAccountId()).orElse(null);
        Account to = accounts.findById(req.toAccountId()).orElse(null);
        if (from == null || to == null) return ResponseEntity.notFound().build();

        if (!me.isAdmin() && !me.getId().equals(from.getOwnerUserId())) {
            Map<String,String> err = new HashMap<>();
            err.put("error","forbidden");
            return ResponseEntity.status(403).body(err);
        }
        if (from.getBalance() < req.amount()) {
            Map<String,String> err = new HashMap<>();
            err.put("error","insufficient funds");
            return ResponseEntity.badRequest().body(err);
        }
        from.setBalance(from.getBalance() - req.amount());
        to.setBalance(to.getBalance() + req.amount());
        accounts.save(from);
        accounts.save(to);
        Map<String,Object> res = new HashMap<>();
        res.put("status","ok");
        res.put("fromRemaining", from.getBalance());
        return ResponseEntity.ok(res);
    }

    // View my accounts
    @GetMapping("/mine")
    public ResponseEntity<?> mine(Authentication auth) {
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "").orElse(null);
        if (me == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(accounts.findByOwnerUserId(me.getId()));
    }
}
