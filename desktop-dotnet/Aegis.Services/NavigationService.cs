using Aegis.Core.Interfaces;
using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Services;

public class NavigationService : INavigationService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly Stack<object> _history = new();

    public object? CurrentView { get; private set; }
    public string CurrentViewName => CurrentView?.GetType().Name.Replace("ViewModel", "") ?? "None";
    public bool CanNavigateBack => _history.Count > 0;

    public event Action? CurrentViewChanged;

    public NavigationService(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public void NavigateTo<TViewModel>() where TViewModel : class
    {
        var vm = _serviceProvider.GetRequiredService<TViewModel>();
        NavigateToInstance(vm);
    }

    public void NavigateTo(Type viewModelType)
    {
        var vm = _serviceProvider.GetRequiredService(viewModelType);
        NavigateToInstance(vm);
    }

    public void NavigateTo<TViewModel>(Action<TViewModel> parameterInitializer) where TViewModel : class
    {
        var vm = _serviceProvider.GetRequiredService<TViewModel>();
        parameterInitializer(vm);
        NavigateToInstance(vm);
    }

    public void NavigateBack()
    {
        if (_history.Count > 0)
        {
            CurrentView = _history.Pop();
            CurrentViewChanged?.Invoke();
        }
    }

    private void NavigateToInstance(object viewModel)
    {
        if (CurrentView != null)
        {
            _history.Push(CurrentView);
        }
        CurrentView = viewModel;
        CurrentViewChanged?.Invoke();
    }
}
