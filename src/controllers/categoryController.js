const db = require('../config/database');

const categoryController = {
    async getAllCategories(req, res) {
        try {
            const userId = req.user.id;
            
            const query = `
                SELECT pc.*
                FROM password_categories pc
                JOIN password_vaults pv ON pc.vault_id = pv.id
                WHERE pv.user_id = $1
                ORDER BY pc.name ASC
            `;
            
            const result = await db.query(query, [userId]);
            res.json(result.rows);
        } catch (error) {
            console.error('Error fetching categories:', error);
            res.status(500).json({ message: 'Server error' });
        }
    },

    async createCategory(req, res) {
        try {
            const userId = req.user.id;
            const { name, description, color, icon } = req.body;

            // Get user's vault
            const vaultResult = await db.query(
                'SELECT id FROM password_vaults WHERE user_id = $1 LIMIT 1',
                [userId]
            );

            if (vaultResult.rows.length === 0) {
                return res.status(404).json({ message: 'Vault not found' });
            }

            const query = `
                INSERT INTO password_categories (vault_id, name, description, color, icon)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING *
            `;

            const result = await db.query(query, [
                vaultResult.rows[0].id,
                name,
                description,
                color,
                icon
            ]);

            res.status(201).json(result.rows[0]);
        } catch (error) {
            console.error('Error creating category:', error);
            res.status(500).json({ message: 'Server error' });
        }
    },

    async updateCategory(req, res) {
        try {
            const userId = req.user.id;
            const categoryId = req.params.id;
            const { name, description, color, icon } = req.body;

            const query = `
                UPDATE password_categories pc
                SET 
                    name = COALESCE($1, pc.name),
                    description = COALESCE($2, pc.description),
                    color = COALESCE($3, pc.color),
                    icon = COALESCE($4, pc.icon),
                    updated_at = CURRENT_TIMESTAMP
                FROM password_vaults pv
                WHERE pc.vault_id = pv.id
                AND pc.id = $5
                AND pv.user_id = $6
                RETURNING pc.*
            `;

            const result = await db.query(query, [
                name,
                description,
                color,
                icon,
                categoryId,
                userId
            ]);

            if (result.rows.length === 0) {
                return res.status(404).json({ message: 'Category not found' });
            }

            res.json(result.rows[0]);
        } catch (error) {
            console.error('Error updating category:', error);
            res.status(500).json({ message: 'Server error' });
        }
    },

    async deleteCategory(req, res) {
        try {
            const userId = req.user.id;
            const categoryId = req.params.id;

            const query = `
                DELETE FROM password_categories pc
                USING password_vaults pv
                WHERE pc.vault_id = pv.id
                AND pc.id = $1
                AND pv.user_id = $2
                RETURNING pc.id
            `;

            const result = await db.query(query, [categoryId, userId]);

            if (result.rows.length === 0) {
                return res.status(404).json({ message: 'Category not found' });
            }

            res.json({ message: 'Category deleted successfully' });
        } catch (error) {
            console.error('Error deleting category:', error);
            res.status(500).json({ message: 'Server error' });
        }
    }
};

module.exports = categoryController;