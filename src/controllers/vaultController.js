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

    async getEntriesForReset(req, res) {
        try {
            const userId = req.user.id; // From temp token middleware
    
            const query = `
                SELECT pe.*
                FROM password_entries pe
                JOIN password_vaults pv ON pe.vault_id = pv.id
                WHERE pv.user_id = $1 AND pe.is_deleted = false
            `;
    
            const result = await db.query(query, [userId]);
            res.json(result.rows);
        } catch (error) {
            console.error('Error fetching entries for reset:', error);
            res.status(500).json({ message: 'Server error' });
        }
    },
    // Get all favorite password entries for a user
    async getFavoriteEntries(req, res) {
        try {
            const userId = req.user.id;
            const query = `
                SELECT pe.*
                FROM password_entries pe
                JOIN password_vaults pv ON pe.vault_id = pv.id
                WHERE pe.favorite = true 
                AND pv.user_id = $1
                AND pe.is_deleted = false
                ORDER BY pe.created_at DESC
            `;
            const result = await db.query(query, [userId]);
            res.json(result.rows);
        } catch (error) {
            console.error('Error fetching favorite password entries:', error);
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
                encrypted_username,
                encrypted_password,
                encrypted_notes,
                website_url,
                category_id,
                favorite
            } = req.body;
            // Validate required fields
            if (!title || !encrypted_username || !encrypted_password) {
                return res.status(400).json({ 
                    message: 'Missing required fields',
                    details: { title, hasUsername: !!encrypted_username, hasPassword: !!encrypted_password }
                });
            }

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
                    category_id,
                    favorite
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING *
            `;

            const values = [
                vaultId,
                title,
                encrypted_username,
                encrypted_password,
                encrypted_notes || null,
                website_url || '',
                category_id || null,
                favorite || false
            ];

            const result = await client.query(query, values);
            await client.query('COMMIT');

            res.status(201).json(result.rows[0]);
        } catch (error) {
            await client.query('ROLLBACK');
            console.error('Error creating password entry:', error);
            res.status(500).json({ 
                message: 'Server error',
                details: error.message 
            });
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
                encrypted_username,
                encrypted_password,
                encrypted_notes,
                website_url,
                category_id,
                favorite,
                isSharedUpdate
            } = req.body;

            let hasAccess = false;

            if (isSharedUpdate) {
                // Only check share access if it's a shared user update
                const shareAccessQuery = `
                    SELECT s.id
                    FROM shared_passwords s
                    WHERE s.entry_id = $1 
                    AND s.shared_with = $2 
                    AND s.permission_level IN ('write', 'admin')
                    AND (s.expires_at IS NULL OR s.expires_at > CURRENT_TIMESTAMP)
                `;
                const shareAccessResult = await client.query(shareAccessQuery, [entryId, userId]);
                console.log("shareAccessResult", shareAccessResult);
                hasAccess = shareAccessResult.rows.length > 0;
            } else {
                // Check ownership for regular updates
                const ownershipQuery = `
                    SELECT pe.id
                    FROM password_entries pe
                    JOIN password_vaults pv ON pe.vault_id = pv.id
                    WHERE pe.id = $1 AND pv.user_id = $2
                `;
                const ownershipResult = await client.query(ownershipQuery, [entryId, userId]);
                hasAccess = ownershipResult.rows.length > 0;
            }

            if (!hasAccess) {
                return res.status(404).json({ message: 'Entry not found or insufficient permissions' });
            }

            // Rest of the update logic remains the same
            const updateQuery = `
                UPDATE password_entries
                SET
                    title = COALESCE($1, title),
                    encrypted_username = COALESCE($2, encrypted_username),
                    encrypted_password = COALESCE($3, encrypted_password),
                    encrypted_notes = COALESCE($4, encrypted_notes),
                    website_url = COALESCE($5, website_url),
                    category_id = $6,
                    favorite = COALESCE($7, favorite),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $8
                RETURNING *
            `;

            const categoryId = req.body.category_id || null; // Convert empty string to null

            const values = [
                title,
                encrypted_username,
                encrypted_password,
                encrypted_notes,
                website_url,
                categoryId,
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
    },

    // Add this method to vaultController
    async getEntryById(req, res) {
        try {
            const userId = req.user.id;
            const entryId = req.params.id;

            const query = `
                SELECT pe.*
                FROM password_entries pe
                JOIN password_vaults pv ON pe.vault_id = pv.id
                WHERE pe.id = $1 AND pv.user_id = $2 AND pe.is_deleted = false
            `;

            const result = await db.query(query, [entryId, userId]);

            if (result.rows.length === 0) {
                return res.status(404).json({ message: 'Entry not found' });
            }

            res.json(result.rows[0]);
        } catch (error) {
            console.error('Error fetching password entry:', error);
            res.status(500).json({ message: 'Server error' });
        }
    },

    // Add a category to a password entry
    async addCategoryToEntry(req, res) {
        try {
            const { id } = req.params;
            const { categoryId } = req.body;

            const query = `
                UPDATE password_entries
                SET category_id = $1
                WHERE id = $2
                RETURNING *
            `;
            const result = await db.query(query, [categoryId, id]);

            if (result.rows.length === 0) {
                return res.status(404).json({ message: 'Entry not found' });
            }

            res.json(result.rows[0]);
        } catch (error) {
            console.error('Error adding category to entry:', error);
            res.status(500).json({ message: 'Server error' });
        }
    },

    // Remove a category from a password entry
    async removeCategoryFromEntry(req, res) {
        try {
            const { id } = req.params;

            const query = `
                UPDATE password_entries
                SET category_id = NULL
                WHERE id = $1
                RETURNING *
            `;
            const result = await db.query(query, [id]);

            if (result.rows.length === 0) {
                return res.status(404).json({ message: 'Entry not found' });
            }

            res.json(result.rows[0]);
        } catch (error) {
            console.error('Error removing category from entry:', error);
            res.status(500).json({ message: 'Server error' });
        }
    }
};

module.exports = vaultController;