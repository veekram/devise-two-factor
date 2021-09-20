module Devise
  module Strategies
    class TwoFactorBackupable < Devise::Strategies::DatabaseAuthenticatable

      def authenticate!
        resource  = password.present? && mapping.to.find_for_database_authentication(authentication_hash)
        hashed = false

        unless resource && validate(resource){ hashed = true; resource.valid_password?(password) }
          mapping.to.new.password = password if !hashed && Devise.paranoid
          return fail!(:not_found_in_database)
        end

        if resource.otp_required_for_login
          return if params[scope].key?('otp_attempt')

          unless validate(resource){ valid_otp_backup?(resource) }
            return fail!(:invalid_otp)
          end
        end

        resource.save!
        remember_me(resource)
        resource.after_database_authentication
        success!(resource)

        mapping.to.new.password = password if !hashed && Devise.paranoid
      end

      private

      def valid_otp_backup?(resource)
        return false if params[scope]['otp_backup'].nil?
        resource.invalidate_otp_backup_code!(params[scope]['otp_backup'])
      end
    end
  end
end

Warden::Strategies.add(:two_factor_backupable, Devise::Strategies::TwoFactorBackupable)
