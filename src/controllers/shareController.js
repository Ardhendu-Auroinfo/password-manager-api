const db = require('../config/database');
const { encryptEmail, decryptEmail } = require('../utils/encryption');
const emailService = require('../services/emailService');

const shareController = {
    async sharePassword(req, res) {
        const client = await db.connect();
        try {
            const { entryId, sharedWithEmail, permissionLevel, expiresAt, sharedKey } = req.body;
            const sharedById = req.user.id;
            console.log('sharedWithEmail', sharedWithEmail);
            const encryptedEmail = encryptEmail(sharedWithEmail);
            console.log('req.user.email', decryptEmail(req.user.email));


            await client.query('BEGIN');

            // Verify ownership of the password entry
            const entryQuery = `
                SELECT pe.* FROM password_entries pe
                JOIN password_vaults pv ON pe.vault_id = pv.id
                WHERE pe.id = $1 AND pv.user_id = $2
            `;
            const entryResult = await client.query(entryQuery, [entryId, sharedById]);
            
            if (entryResult.rows.length === 0) {
                throw new Error('Password entry not found or unauthorized');
            }

            // Get recipient user
            const userQuery = 'SELECT id FROM users WHERE email = $1';
            const userResult = await client.query(userQuery, [encryptedEmail]);

            if (userResult.rows.length === 0) {
                throw new Error('Recipient user not found');
            }

            const sharedWithId = userResult.rows[0].id;

            // Create shared password entry
            const shareQuery = `
                INSERT INTO shared_passwords (
                    entry_id, shared_by, shared_with, 
                    permission_level, expires_at, shared_key
                )
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id
            `;

            await client.query(shareQuery, [
                entryId,
                sharedById,
                sharedWithId,
                permissionLevel,
                expiresAt,
                sharedKey
            ]);

            await client.query('COMMIT');
            const sharedByEmail = decryptEmail(req.user.email);
            await emailService.sendShareNotification(sharedWithEmail, sharedByEmail, entryResult.rows[0].title);
            res.status(201).json({ message: 'Password shared successfully' });
        } catch (error) {
            await client.query('ROLLBACK');
            console.error('Error sharing password:', error);
            res.status(500).json({ message: error.message });
        } finally {
            client.release();
        }
    },

    async getSharedPasswords(req, res) {
        try {
            const userId = req.user.id;
            
            const query = `
                SELECT 
                    sp.*,
                    pe.title,
                    pe.website_url,
                    pe.encrypted_username,
                    pe.encrypted_password,
                    pe.encrypted_notes,
                    u.email as shared_by_email,
                    sp.shared_key
                FROM shared_passwords sp
                JOIN password_entries pe ON sp.entry_id = pe.id
                JOIN users u ON sp.shared_by = u.id
                WHERE sp.shared_with = $1 
                AND (sp.expires_at IS NULL OR sp.expires_at > CURRENT_TIMESTAMP)
            `;

            const result = await db.query(query, [userId]);
            
            // Decrypt shared_by_email for each row
            const decryptedResults = result.rows.map(row => ({
                ...row,
                shared_by_email: decryptEmail(row.shared_by_email)
            }));

            res.json(decryptedResults);
        } catch (error) {
            console.error('Error fetching shared passwords:', error);
            res.status(500).json({ message: 'Server error' });
        }
    },
    async getSharedByMePasswords(req, res) {
        try {
            const userId = req.user.id;
            
            const query = `
                SELECT 
                    sp.*,
                    pe.title,
                    pe.website_url,
                    pe.encrypted_username,
                    pe.encrypted_password,
                    pe.encrypted_notes,
                    u.email as shared_with_email,
                    sp.shared_key
                FROM shared_passwords sp
                JOIN password_entries pe ON sp.entry_id = pe.id
                JOIN users u ON sp.shared_with = u.id
                WHERE sp.shared_by = $1 
                AND (sp.expires_at IS NULL OR sp.expires_at > CURRENT_TIMESTAMP)
            `;
    
            const result = await db.query(query, [userId]);
            
            // Decrypt shared_with_email for each row
            const decryptedResults = result.rows.map(row => ({
                ...row,
                shared_with_email: decryptEmail(row.shared_with_email)
            }));

            res.json(decryptedResults);
        } catch (error) {
            console.error('Error fetching shared by me passwords:', error);
            res.status(500).json({ message: 'Server error' });
        }
    },
    async revokeAccess(req, res) {
        const { id } = req.params;
        console.log('Revoking access for shared password with ID:', id);
        const client = await db.connect();
        try {
            await client.query('DELETE FROM shared_passwords WHERE id = $1', [id]);
            res.status(200).json({ message: 'Access revoked successfully' });
        } catch (error) {
            console.error('Error revoking access:', error);
            res.status(500).json({ message: 'Server error' });
        } finally {
            client.release();
        }
    }
};

module.exports = shareController;