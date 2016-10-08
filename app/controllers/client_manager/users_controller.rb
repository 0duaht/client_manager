require_dependency "client_manager/application_controller"


module ClientManager
  class UsersController < ApplicationController
    before_action :authenticate_superadmin
    before_action :set_user, only: [:destroy, :update, :edit]

    def new
      @user = User.new
    end

    def index
      @users = User.all.select { |x| x != current_user }
    end

    def edit
      @can_edit_email = @user.password_changed
    end

    def update
      if params[:user][:maximum_number_of_clients].to_i < @user.clients.count
        flash[:error] = "User already has more clients. Max. number of clients can't be lower."
      elsif @user.update(user_params)
        flash[:success] = "User successfully updated"
      else
        flash[:error] = @user.errors.empty? ? "Error" : @user.errors.full_messages.to_sentence
      end
      redirect_to users_path

    end

    def create
      @user = User.new(user_params)
      if @user.save
        flash[:success] = "User successfully created"
      else
        flash[:error] = @user.errors.empty? ? "Error" : @user.errors.full_messages.to_sentence
      end
      redirect_to users_path
    end


    def destroy
      @user.destroy
      flash[:success] = "User successfully deleted"
      redirect_to users_path
    end


    private


    def set_user
      @user = User.find(params[:id])
    end

    def user_params
      params.require(:user).permit(:name, :email, :maximum_number_of_clients)
    end
  end
end
