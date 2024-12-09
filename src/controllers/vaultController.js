const db = require('../config/database');

const vaultController = {
    // Get all password entries for a user
    async getAllEntries(req, res) {
        try {
            const userId = req.user.id; // From auth middleware

            const query = `
                SELECT pe.*, pv.name as vault_name
                FROM password_entries pe
                JOIN password_vaults pv ON pe.vault_id = pv.id
                WHERE pv.user_id = $1 AND pe.is_deleted = false
                ORDER BY pe.created_at DESC
            `;

            const result = await db.query(query, [userId]);
            res.json(result.rows);
        } catch (error) {
            console.error('Error fetching password entries:', error);
            res.status(500).json({ message: 'Server error' });
        }
    },

    // Create new password entry
    async createEntry(req, res) {
        const client = await db.connect();
        try {
            const userId = req.user.id;
            const {
                title,
                username,
                password,
                notes,
                website_url,
                category,
                favorite
            } = req.body;

            // Start transaction
            await client.query('BEGIN');

            // Get user's default vault
            const vaultResult = await client.query(
                'SELECT id FROM password_vaults WHERE user_id = $1 LIMIT 1',
                [userId]
            );

            if (vaultResult.rows.length === 0) {
                throw new Error('No vault found for user');
            }

            const vaultId = vaultResult.rows[0].id;

            const query = `
                INSERT INTO password_entries (
                    vault_id,
                    title,
                    encrypted_username,
                    encrypted_password,
                    encrypted_notes,
                    website_url,
                    category,
                    favorite
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING *
            `;

            const values = [
                vaultId,
                title,
                username,    // Will be encrypted on frontend
                password,    // Will be encrypted on frontend
                notes,      // Will be encrypted on frontend
                website_url,
                category,
                favorite || false
            ];

            const result = await client.query(query, values);
            await client.query('COMMIT');

            res.status(201).json(result.rows[0]);
        } catch (error) {
            await client.query('ROLLBACK');
            console.error('Error creating password entry:', error);
            res.status(500).json({ message: 'Server error' });
        } finally {
            client.release();
        }
    },

    // Update password entry
    async updateEntry(req, res) {
        const client = await db.connect();
        try {
            const userId = req.user.id;
            const entryId = req.params.id;
            const {
                title,
                username,
                password,
                notes,
                website_url,
                category,
                favorite
            } = req.body;

            // Verify ownership
            const verifyQuery = `
                SELECT pe.id
                FROM password_entries pe
                JOIN password_vaults pv ON pe.vault_id = pv.id
                WHERE pe.id = $1 AND pv.user_id = $2
            `;

            const verifyResult = await client.query(verifyQuery, [entryId, userId]);
            if (verifyResult.rows.length === 0) {
                return res.status(404).json({ message: 'Entry not found' });
            }

            // Start transaction
            await client.query('BEGIN');

            // Store old password in history if password is being updated
            if (password) {
                const historyQuery = `
                    INSERT INTO password_history (entry_id, encrypted_password)
                    SELECT id, encrypted_password
                    FROM password_entries
                    WHERE id = $1
                `;
                await client.query(historyQuery, [entryId]);
            }

            // Update entry
            const updateQuery = `
                UPDATE password_entries
                SET
                    title = COALESCE($1, title),
                    encrypted_username = COALESCE($2, encrypted_username),
                    encrypted_password = COALESCE($3, encrypted_password),
                    encrypted_notes = COALESCE($4, encrypted_notes),
                    website_url = COALESCE($5, website_url),
                    category = COALESCE($6, category),
                    favorite = COALESCE($7, favorite),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $8
                RETURNING *
            `;

            const values = [
                title,
                username,    // Encrypted on frontend
                password,    // Encrypted on frontend
                notes,      // Encrypted on frontend
                website_url,
                category,
                favorite,
                entryId
            ];

            const result = await client.query(updateQuery, values);
            await client.query('COMMIT');

            res.json(result.rows[0]);
        } catch (error) {
            await client.query('ROLLBACK');
            console.error('Error updating password entry:', error);
            res.status(500).json({ message: 'Server error' });
        } finally {
            client.release();
        }
    },

    // Delete password entry (soft delete)
    async deleteEntry(req, res) {
        try {
            const userId = req.user.id;
            const entryId = req.params.id;

            const query = `
                UPDATE password_entries pe
                SET is_deleted = true
                FROM password_vaults pv
                WHERE pe.vault_id = pv.id
                AND pe.id = $1
                AND pv.user_id = $2
                RETURNING pe.id
            `;

            const result = await db.query(query, [entryId, userId]);

            if (result.rows.length === 0) {
                return res.status(404).json({ message: 'Entry not found' });
            }

            res.json({ message: 'Entry deleted successfully' });
        } catch (error) {
            console.error('Error deleting password entry:', error);
            res.status(500).json({ message: 'Server error' });
        }
    },

    // Search password entries
    async searchEntries(req, res) {
        try {
            const userId = req.user.id;
            const searchQuery = req.query.q;

            const query = `
                SELECT pe.*
                FROM password_entries pe
                JOIN password_vaults pv ON pe.vault_id = pv.id
                WHERE pv.user_id = $1
                AND pe.is_deleted = false
                AND (
                    pe.title ILIKE $2
                    OR pe.website_url ILIKE $2
                    OR pe.category ILIKE $2
                )
                ORDER BY pe.title
            `;

            const result = await db.query(query, [userId, `%${searchQuery}%`]);
            res.json(result.rows);
        } catch (error) {
            console.error('Error searching password entries:', error);
            res.status(500).json({ message: 'Server error' });
        }
    }
};

module.exports = vaultController;